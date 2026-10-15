//! Output conventions (CLI.md): stdout is for results, stderr is for
//! narration. `--quiet` drops narration, `--verbose` adds decisions and the
//! command line of every subprocess ward starts, and color appears only
//! on a terminal, only on stderr, only on the words that carry state.
//!
//! Quiet is implemented at the file-descriptor level: fd 2 is pointed at
//! /dev/null after one private copy of the original stderr is kept for
//! errors. That silences every module's `eprintln!` and every subprocess
//! (uv, npm, cargo, ...) without threading a flag through them, and it
//! guarantees the one thing quiet must never hide: the error. A panic is
//! an error, so the panic hook writes through that saved copy too.

use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Default)]
struct Settings {
    quiet: bool,
    verbose: bool,
    color: bool,
}

static SETTINGS: OnceLock<Settings> = OnceLock::new();
/// The saved original stderr when quiet redirected fd 2.
static ERROR_FD: OnceLock<i32> = OnceLock::new();

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

fn settings() -> Settings {
    SETTINGS.get().copied().unwrap_or_default()
}

/// Apply the global options once, before any command runs. Repeated calls
/// keep the first settings.
pub fn init(quiet: bool, verbose: bool, no_color: bool) -> io::Result<()> {
    if SETTINGS.get().is_some() {
        return Ok(());
    }
    let color = !no_color && std::env::var_os("NO_COLOR").is_none() && io::stderr().is_terminal();
    let _ = SETTINGS.set(Settings {
        quiet,
        verbose: verbose && !quiet,
        color,
    });
    if verbose && !quiet {
        // The phase table's "total" row runs from here.
        let _ = WALL_START.set(Instant::now());
    }
    if quiet {
        silence_stderr()?;
    }
    install_panic_hook();
    Ok(())
}

/// A panic must reach the user whatever `--quiet` did to fd 2: the default
/// hook writes to fd 2, which quiet points at /dev/null, so the process
/// would exit 101 having printed nothing. It goes through the error channel
/// in every mode, so its message has the signing key's secret replaced like
/// any other ([`scrub`]); `RUST_BACKTRACE` still adds the backtrace.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(move |info| {
        // A download may be holding the cursor's row. Clear it first, or
        // the panic prints onto the tail of the progress line.
        erase_progress_line();
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|text| (*text).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panicked".to_string());
        let where_ = match info.location() {
            Some(location) => format!(" at {}:{}", location.file(), location.line()),
            None => String::new(),
        };
        // RUST_BACKTRACE asks for the backtrace, as with the default hook.
        let wanted = std::env::var_os("RUST_BACKTRACE").is_some_and(|value| value != "0");
        let backtrace = if wanted {
            format!("{}\n", std::backtrace::Backtrace::force_capture())
        } else {
            String::new()
        };
        write_error_channel(&format!(
            "ward: {}: {payload}{where_}\nward: this is a bug in ward; please report it with the command you ran\n{backtrace}",
            paint("internal error", RED)
        ));
    }));
}

fn silence_stderr() -> io::Result<()> {
    let null = std::fs::OpenOptions::new().write(true).open("/dev/null")?;
    // The saved copy is close-on-exec so no child inherits the real stderr.
    let saved = dup_cloexec(io::stderr().as_raw_fd())?;
    // SAFETY: plain fd duplication on fds this process owns.
    if unsafe { libc::dup2(null.as_raw_fd(), io::stderr().as_raw_fd()) } < 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::close(saved) };
        return Err(error);
    }
    let _ = ERROR_FD.set(saved);
    Ok(())
}

pub fn quiet() -> bool {
    settings().quiet
}

/// Run `job` with fd 1 pointed at fd 2, so whatever it or any child it
/// spawns prints reaches stderr, then put fd 1 back. `ward env` syncs
/// before it prints and its stdout is evaled by a shell: a package
/// manager's summary there would be executed as commands.
pub fn with_stdout_on_stderr<T>(job: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    with_fd_pointed_at(io::stdout().as_raw_fd(), io::stderr().as_raw_fd(), job)
}

/// Run `job` with fd 2 on the real stderr, then put it back. `--quiet`
/// means "errors and results only": it silences ward's own sync tools, but
/// the program the user asked for (`run`, a script, `x`, a file, `fmt`,
/// `build`) is theirs, and its tracebacks and compiler errors are the
/// errors. Without `--quiet` fd 2 already is the real stderr.
pub fn with_users_stderr<T>(job: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    match ERROR_FD.get() {
        Some(&real) => with_fd_pointed_at(io::stderr().as_raw_fd(), real, job),
        None => job(),
    }
}

/// The mechanism, over any two descriptors so it can be tested against a
/// pipe. Rust's own stdout buffer is flushed first, so nothing written
/// before the swap comes out after it on the wrong side.
fn with_fd_pointed_at<T>(
    fd: i32,
    target: i32,
    job: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    io::stdout().flush()?;
    let saved = dup_cloexec(fd)?;
    // SAFETY: plain duplication of descriptors this process owns.
    if unsafe { libc::dup2(target, fd) } < 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::close(saved) };
        return Err(error);
    }
    // From here the guard puts `fd` back and closes the saved copy on every
    // path: a job that fails, a flush that fails, and a job that panics.
    let guard = Restore { fd, saved };
    let result = job();
    let flushed = io::stdout().flush();
    let restored = guard.restore();
    let result = result?;
    flushed?;
    restored?;
    Ok(result)
}

/// The descriptor [`with_fd_pointed_at`] swapped, and the copy of what it
/// named before. Dropped without [`Restore::restore`] (a panic), it still
/// puts the descriptor back.
struct Restore {
    fd: i32,
    saved: i32,
}

impl Restore {
    fn restore(self) -> io::Result<()> {
        let this = ManuallyDrop::new(self);
        this.put_back()
    }

    fn put_back(&self) -> io::Result<()> {
        // SAFETY: `saved` is a descriptor this guard owns and closes once.
        let restored = unsafe { libc::dup2(self.saved, self.fd) } >= 0;
        let error = io::Error::last_os_error();
        unsafe { libc::close(self.saved) };
        if restored {
            Ok(())
        } else {
            Err(error)
        }
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = io::stdout().flush();
        let _ = self.put_back();
    }
}

/// A close-on-exec copy of `fd`, made in one call: the proxy and relay
/// threads spawn children, and a fork between a plain `dup` and a later
/// `fcntl(FD_CLOEXEC)` would hand a child the copy.
fn dup_cloexec(fd: i32) -> io::Result<i32> {
    // SAFETY: fcntl duplicates a descriptor this process owns.
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(copy)
}

pub fn verbose() -> bool {
    settings().verbose
}

pub fn color() -> bool {
    settings().color
}

fn paint(word: &str, code: &str) -> String {
    if color() {
        format!("{code}{word}{RESET}")
    } else {
        word.to_string()
    }
}

/// `text` with the signing key's secret replaced wherever it appears: a
/// message can quote a file a parser failed on, and a project file can be
/// the key under another name.
fn scrub(text: &str) -> String {
    crate::kernel::resolve::confine::scrub_signing_key(text)
}

/// Write to the real stderr even under `--quiet`, the signing key's secret
/// replaced ([`scrub`]).
fn write_error_channel(text: &str) {
    let text = scrub(text);
    match ERROR_FD.get() {
        Some(&fd) => {
            // SAFETY: fd is a valid, open descriptor this module saved and
            // never closes; ManuallyDrop keeps File from closing it.
            let mut file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
            let _ = file.write_all(text.as_bytes());
        }
        None => {
            let _ = io::stderr().write_all(text.as_bytes());
        }
    }
}

/// A failure the command could not recover from. Always visible.
pub fn error(message: &str) {
    write_error_channel(&format!("ward: {}: {message}\n", paint("error", RED)));
}

/// A failure with one command that is the way out: the error line, then the
/// same `fix:` line an advisory carries. Always visible, like `error`.
pub fn error_with_fix(message: &str, fix: &str) {
    debug_assert_command(message, fix);
    write_error_channel(&format!(
        "ward: {}: {message}\n{}",
        paint("error", RED),
        fix_line(fix)
    ));
}

/// A command's failure for `--json` (`error_with_fix`'s counterpart):
/// `error`, then `fix` when there is one
/// command that is the way out, and `class` when the failure has one
/// (`kernel::error::Class::name`), so a script can branch on it without
/// reading the message.
pub fn failure_json(message: &str, fix: Option<&str>, class: Option<&str>) {
    let mut object = serde_json::json!({ "error": message });
    if let Some(fix) = fix {
        object["fix"] = fix.into();
    }
    if let Some(class) = class {
        object["class"] = class.into();
    }
    write_error_channel(&format!("{object}\n"));
}

/// The same failure for a `--json` command: one JSON object on stderr, so
/// stdout carries the document or nothing at all and a script never parses
/// prose. Never colored: this line is read by a program.
pub fn error_json(message: &str) {
    let object = serde_json::json!({ "error": message });
    write_error_channel(&format!("{object}\n"));
}

/// The prefix of an advisory's first line, before color is applied. The
/// tests hold `advisory_line` to it.
#[cfg(test)]
pub(crate) const WARNING_PREFIX: &str = "ward: warning: ";
/// The prefix of the fix line. The same 14 columns as `WARNING_PREFIX`, so
/// `fix:` right-aligns under `warning:`.
#[cfg(test)]
pub(crate) const FIX_PREFIX: &str = "ward:     fix: ";
/// The prefix of the next line, for the rare warning whose best command
/// explains the condition rather than clears it. The same 14 columns again,
/// so its command starts where a fix's would.
pub(crate) const NEXT_PREFIX: &str = "ward:    next: ";

/// Something the user should know that did not stop the command, and the
/// one command that resolves it. Suppressed by `--quiet` like all
/// narration.
///
/// `fix` is a command to paste into a shell: no leading "run", no trailing
/// period, no explanation — the explanation is the message. An advisory
/// with nothing for the user to do is not a warning; it is progress, so
/// print it with `note`. One whose only command explains the condition
/// without clearing it is `warning_next`.
pub fn warning(message: &str, fix: &str) {
    if quiet() {
        return;
    }
    eprint!("{}", scrub(&warning_lines(message, fix)));
}

/// Both lines as text, newlines included, for a caller that writes to a
/// handle of its own and must still look like every other advisory.
pub fn warning_lines(message: &str, fix: &str) -> String {
    debug_assert_command(message, fix);
    format!("{}{}", advisory_line(message), fix_line(fix))
}

/// A warning whose best command shows why the condition holds but does not
/// clear it: a probe's own output, or a report that judges what was
/// recorded. Labelled `next:` so nobody pastes it expecting the warning to
/// go away. Prefer `warning` whenever a command that resolves it exists.
pub fn warning_next(message: &str, next: &str) {
    if quiet() {
        return;
    }
    eprint!("{}", scrub(&warning_next_lines(message, next)));
}

/// `warning_next` as text, the way `warning_lines` is `warning`'s.
pub fn warning_next_lines(message: &str, next: &str) -> String {
    debug_assert_command(message, next);
    format!("{}{}", advisory_line(message), next_line(next))
}

/// The second line of either kind is a command to paste, never prose.
fn debug_assert_command(message: &str, command: &str) {
    debug_assert!(
        !command.trim().is_empty(),
        "a warning names the command to type next: {message}"
    );
    debug_assert!(
        !command.starts_with("run ") && !command.starts_with("Run "),
        "the second line is a command, not a sentence about one: {command}"
    );
}

/// The first of the two lines, colored for the current terminal.
pub(crate) fn advisory_line(message: &str) -> String {
    format!("ward: {}: {message}\n", paint("warning", YELLOW))
}

/// The second of the two lines, colored for the current terminal. Green,
/// like `synced`: it is the way out, not the problem.
pub(crate) fn fix_line(command: &str) -> String {
    format!("ward:     {}: {command}\n", paint("fix", GREEN))
}

/// The `next:` line. Uncolored: it is neither the problem nor the way out,
/// only where to look.
pub(crate) fn next_line(command: &str) -> String {
    format!("{NEXT_PREFIX}{command}\n")
}

/// Progress narration.
pub fn note(message: &str) {
    if quiet() {
        return;
    }
    eprintln!("ward: {}", scrub(message));
}

/// A handle for narration a lower layer renders itself: the GC reports
/// write to any `Write`, so their tests can capture them. `--quiet` still silences it, at the descriptor level.
/// Every line written through it starts with `ward: `, like `note`.
pub fn narration() -> io::StderrLock<'static> {
    io::stderr().lock()
}

/// The line each ecosystem prints when its projection is in place.
pub fn synced(what: &str, target: &std::path::Path) {
    if quiet() {
        return;
    }
    eprintln!("{}: {what} -> {}", paint("synced", GREEN), target.display());
}

/// How often a download redraws its progress line. Slow enough that a
/// fast local mirror cannot flood a terminal, fast enough to look live.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Bytes as a human reads them: three significant figures and a unit, so
/// the line does not change width every redraw.
pub(crate) fn human_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
        ("B", 1),
    ];
    for (unit, scale) in UNITS {
        if bytes >= scale {
            if scale == 1 {
                return format!("{bytes} B");
            }
            return format!("{:.1} {unit}", bytes as f64 / scale as f64);
        }
    }
    "0 B".to_string()
}

/// The one-line body of a download's progress report. Pure, so the shape
/// is testable without a terminal.
pub(crate) fn progress_line(what: &str, done: u64, total: Option<u64>) -> String {
    match total {
        Some(total) if total > 0 => {
            let percent = (done.min(total) as f64 / total as f64 * 100.0).round() as u64;
            format!(
                "downloading {what}  {} / {} ({percent}%)",
                human_bytes(done),
                human_bytes(total)
            )
        }
        _ => format!("downloading {what}  {}", human_bytes(done)),
    }
}

/// The one-line body of a batch of concurrent downloads: how many of the
/// batch have finished and the bytes moved so far. Pure, like
/// `progress_line`.
pub(crate) fn batch_line(finished: usize, total: usize, bytes: u64) -> String {
    format!(
        "downloading {finished}/{total} artifacts  {}",
        human_bytes(bytes)
    )
}

/// A download's progress on stderr, redrawn in place and erased when it
/// ends. Narration, so `--quiet` silences it; a redrawn line is noise in a
/// log file, so a stderr that is not a terminal gets nothing either. The
/// value is inert in both cases, so callers need no branch.
///
/// Inside a [`Batch`] (a download running on one of `fetch`'s pool
/// threads) it draws nothing itself: there is one cursor row, so its bytes
/// go to the batch's single line instead.
pub struct Progress {
    what: String,
    total: Option<u64>,
    done: u64,
    drawn: bool,
    live: bool,
    next: Instant,
    batch: Option<std::sync::Arc<Batch>>,
}

impl Progress {
    /// Start reporting a download of `what` (the artifact's name), with its
    /// total size when the server declared one.
    pub fn start(what: &str, total: Option<u64>) -> Self {
        let batch = CURRENT_BATCH.with(|current| current.borrow().clone());
        Self {
            what: what.to_string(),
            total,
            done: 0,
            drawn: false,
            live: batch.is_none() && !quiet() && io::stderr().is_terminal(),
            next: Instant::now(),
            batch,
        }
    }

    /// Account for `bytes` more, redrawing at most once per interval.
    ///
    /// Every write is ignored on failure: a closed or full stderr must not
    /// take down a download that is otherwise fine, and `eprint!` panics
    /// where `write!` returns.
    pub fn advance(&mut self, bytes: u64) {
        self.done = self.done.saturating_add(bytes);
        if let Some(batch) = &self.batch {
            batch.advance(bytes, false);
            return;
        }
        if !self.live {
            return;
        }
        let now = Instant::now();
        if now < self.next {
            return;
        }
        self.next = now + PROGRESS_INTERVAL;
        // \x1b[K clears the rest of the row, so a shorter line never leaves
        // the tail of a longer one behind.
        let mut stderr = io::stderr();
        let _ = write!(
            stderr,
            "\rward: {}\x1b[K",
            progress_line(&self.what, self.done, self.total)
        );
        let _ = stderr.flush();
        self.drawn = true;
        LINE_HELD.store(true, Ordering::Relaxed);
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if self.live && self.drawn {
            erase_progress_line();
        }
    }
}

/// One progress line for downloads that run at once (`fetch::fetch_each`):
/// several `Progress` lines would fight over the one cursor row, so the
/// pool's threads report into this and it draws
/// `downloading 12/70 artifacts  34.0 MiB`. The pool drops it before it
/// returns, which erases the line, so nothing a caller prints afterwards (a
/// warning and its `fix:` line) lands on its tail. Inert under `--quiet`
/// and off a terminal, like `Progress`.
pub struct Batch {
    total: usize,
    live: bool,
    state: std::sync::Mutex<BatchState>,
}

struct BatchState {
    finished: usize,
    bytes: u64,
    drawn: bool,
    next: Instant,
}

thread_local! {
    /// The batch this thread's downloads report into, while it runs one of
    /// the pool's jobs ([`in_batch`]).
    static CURRENT_BATCH: std::cell::RefCell<Option<std::sync::Arc<Batch>>> =
        const { std::cell::RefCell::new(None) };
}

impl Batch {
    /// Start a batch of `total` downloads.
    pub fn start(total: usize) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            total,
            live: !quiet() && io::stderr().is_terminal(),
            state: std::sync::Mutex::new(BatchState {
                finished: 0,
                bytes: 0,
                drawn: false,
                next: Instant::now(),
            }),
        })
    }

    /// One of the batch's downloads is over, cache hit or not.
    pub fn finished(&self) {
        self.advance(0, true);
    }

    /// Account for `bytes` more, and one more finished download when
    /// `finished`, redrawing at most once per interval. Writes are ignored
    /// on failure, as `Progress::advance`'s are. The lock is held across
    /// the write, so two threads never interleave one line.
    fn advance(&self, bytes: u64, finished: bool) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.bytes = state.bytes.saturating_add(bytes);
        state.finished += usize::from(finished);
        if !self.live {
            return;
        }
        let now = Instant::now();
        if now < state.next {
            return;
        }
        state.next = now + PROGRESS_INTERVAL;
        let mut stderr = io::stderr();
        let _ = write!(
            stderr,
            "\rward: {}\x1b[K",
            batch_line(state.finished, self.total, state.bytes)
        );
        let _ = stderr.flush();
        state.drawn = true;
        LINE_HELD.store(true, Ordering::Relaxed);
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        let drawn = self
            .state
            .get_mut()
            .map(|state| state.drawn)
            .unwrap_or_else(|poisoned| poisoned.into_inner().drawn);
        if self.live && drawn {
            erase_progress_line();
        }
    }
}

/// Run `job` with this thread's downloads reporting into `batch`. A pool
/// thread calls it around its work: a thread-local is not inherited, so
/// the spawner cannot set it for the thread.
pub fn in_batch<T>(batch: &std::sync::Arc<Batch>, job: impl FnOnce() -> T) -> T {
    /// Clears the thread's batch on the way out, a panic included.
    struct Leave;
    impl Drop for Leave {
        fn drop(&mut self) {
            CURRENT_BATCH.with(|current| current.borrow_mut().take());
        }
    }
    CURRENT_BATCH.with(|current| *current.borrow_mut() = Some(std::sync::Arc::clone(batch)));
    let _leave = Leave;
    job()
}

/// Is a progress line currently occupying the cursor's row? The panic hook
/// reads this so a crash mid-download does not print its message onto the
/// tail of `downloading cpython-3.12.14.tar.gz  12.0 MiB / 28.3 MiB (42%)`.
static LINE_HELD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
use std::sync::atomic::Ordering;

/// Return the cursor to a clean row if a progress line is holding it.
/// Idempotent, and a no-op when nothing was drawn.
fn erase_progress_line() {
    if !LINE_HELD.swap(false, Ordering::Relaxed) {
        return;
    }
    let mut stderr = io::stderr();
    let _ = write!(stderr, "\r\x1b[K");
    let _ = stderr.flush();
}

/// An argv rendered as a shell line the user can paste back.
pub fn shell_line<S: AsRef<str>>(argv: &[S]) -> String {
    argv.iter()
        .map(|word| shell_word(word.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decision-level detail, only under `--verbose`.
pub fn trace(message: &str) {
    if verbose() {
        eprintln!("ward: {} {message}", paint("[verbose]", DIM));
    }
}

/// The command line of a subprocess ward is about to start, only under
/// `--verbose`; the bug-report mode's most useful line.
pub fn trace_command(command: &std::process::Command) {
    if !verbose() {
        return;
    }
    let mut line = shell_word(&command.get_program().to_string_lossy());
    for arg in command.get_args() {
        line.push(' ');
        line.push_str(&shell_word(&arg.to_string_lossy()));
    }
    let cwd = command
        .get_current_dir()
        .map(|dir| format!(" (in {})", dir.display()))
        .unwrap_or_default();
    trace(&format!("run: {line}{cwd}"));
}

fn shell_word(word: &str) -> String {
    if !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@+,".contains(c))
    {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// Phase timings for `--verbose`: where a sync's wall time went.
///
/// `let _t = ui::phase("artifact fetch");` times the rest of the scope and
/// adds it to the row of that name. A phase opened while another is open
/// on the same thread is nested under it, and the table shows it indented
/// under its parent, already counted there. A thread of a pool starts its
/// phases under the caller's with `current_phase`. Without `--verbose`
/// the guard is inert: no clock is read and nothing is recorded.
static PHASES: PhaseLog = PhaseLog::new();
/// When `init` turned `--verbose` on: the table's "total" row runs from
/// here.
static WALL_START: OnceLock<Instant> = OnceLock::new();

thread_local! {
    /// The path of the phase open on this thread, outermost first.
    static OPEN_PHASE: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// One row of the table: a phase's path from the top level, the wall time
/// it accumulated, and how many times it ran.
#[derive(Debug, Clone, PartialEq)]
struct PhaseRow {
    path: Vec<String>,
    total: Duration,
    count: u32,
}

/// Every phase one process timed, in the order each was first opened.
/// Shared by every thread, so a download pool adds to the same rows.
struct PhaseLog {
    rows: std::sync::Mutex<Vec<PhaseRow>>,
}

impl PhaseLog {
    const fn new() -> Self {
        Self {
            rows: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<PhaseRow>> {
        self.rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Open `name` under `parent`, or under the phase open on this thread
    /// when `parent` is `None`. The row, and every ancestor's, exists from
    /// now on, so the table lists phases in the order they started.
    fn start(&self, name: &str, parent: Option<&[String]>) -> Phase<'_> {
        let previous = OPEN_PHASE.with(|open| open.borrow().clone());
        let mut path = parent.map_or_else(|| previous.clone(), <[String]>::to_vec);
        path.push(name.to_string());
        {
            let mut rows = self.lock();
            for depth in 1..=path.len() {
                if !rows.iter().any(|row| row.path == path[..depth]) {
                    rows.push(PhaseRow {
                        path: path[..depth].to_vec(),
                        total: Duration::ZERO,
                        count: 0,
                    });
                }
            }
        }
        OPEN_PHASE.with(|open| *open.borrow_mut() = path.clone());
        Phase {
            open: Some(OpenPhase {
                log: self,
                path,
                previous,
                started: Instant::now(),
            }),
            _thread_bound: std::marker::PhantomData,
        }
    }

    fn add(&self, path: &[String], elapsed: Duration) {
        let mut rows = self.lock();
        if let Some(row) = rows.iter_mut().find(|row| row.path == path) {
            row.total += elapsed;
            row.count += 1;
        }
    }

    fn rows(&self) -> Vec<PhaseRow> {
        self.lock().clone()
    }
}

/// A phase being timed; dropping it adds the elapsed wall time to its row.
/// Bound to the thread that opened it, because it restores that thread's
/// open path when it drops.
#[must_use = "a phase is timed until its guard drops: bind it with `let _t = ...`"]
pub struct Phase<'a> {
    open: Option<OpenPhase<'a>>,
    _thread_bound: std::marker::PhantomData<*const ()>,
}

struct OpenPhase<'a> {
    log: &'a PhaseLog,
    path: Vec<String>,
    previous: Vec<String>,
    started: Instant,
}

impl Phase<'_> {
    fn inert() -> Phase<'static> {
        Phase {
            open: None,
            _thread_bound: std::marker::PhantomData,
        }
    }
}

impl Drop for Phase<'_> {
    fn drop(&mut self) {
        if let Some(open) = self.open.take() {
            open.log.add(&open.path, open.started.elapsed());
            OPEN_PHASE.with(|current| *current.borrow_mut() = open.previous);
        }
    }
}

/// Time the rest of the caller's scope as `name`, under `--verbose` only.
pub fn phase(name: &str) -> Phase<'static> {
    if !verbose() {
        return Phase::inert();
    }
    PHASES.start(name, None)
}

/// Run `job` as the phase `name`: [`phase`] for one expression.
pub fn timed<T>(name: &str, job: impl FnOnce() -> T) -> T {
    let _t = phase(name);
    job()
}

/// The phase open on this thread, to open phases under from another
/// thread: a pool worker's `parent.phase("artifact fetch")` is a child of
/// the phase that started the pool, not a second top-level row. Test-only
/// until the parallel download pool (#745) is its first caller.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct PhaseParent(Option<Vec<String>>);

/// The phase open on this thread, for [`PhaseParent::phase`].
#[cfg(test)]
pub fn current_phase() -> PhaseParent {
    if !verbose() {
        return PhaseParent(None);
    }
    PhaseParent(Some(OPEN_PHASE.with(|open| open.borrow().clone())))
}

#[cfg(test)]
impl PhaseParent {
    /// Time the rest of the caller's scope as `name`, nested under the
    /// phase this was taken from, on whatever thread calls it.
    pub fn phase(&self, name: &str) -> Phase<'static> {
        match &self.0 {
            Some(path) => PHASES.start(name, Some(path)),
            None => Phase::inert(),
        }
    }
}

/// Print the phase table on stderr, under `--verbose` only, when anything
/// was timed. `main` calls it once a sync or a dependency edit finishes,
/// before any error, so a failure is still the last line on screen.
pub fn print_phase_table() {
    if !verbose() {
        return;
    }
    let rows = PHASES.rows();
    if rows.is_empty() {
        return;
    }
    let wall = WALL_START.get().map(Instant::elapsed);
    write_phase_table(&rows, wall, &mut io::stderr().lock());
}

fn write_phase_table(rows: &[PhaseRow], wall: Option<Duration>, output: &mut impl Write) {
    // A timing report must not turn a successful command into a failure
    // when stderr is closed or full.
    for line in render_phases(rows, wall).lines() {
        let _ = writeln!(output, "ward: {} {line}", paint("[verbose]", DIM));
    }
}

/// The table as text, one line per row. Top-level rows come first in the
/// order they started, each followed by its nested rows, indented and
/// marked with `-`: those are already counted in the row above them, so
/// only the top-level rows sum to the total. A phase that ran more than
/// once says how many times; a pool's phases can add up to more than the
/// row they sit under, because they overlapped.
fn render_phases(rows: &[PhaseRow], wall: Option<Duration>) -> String {
    let mut ordered: Vec<(String, Duration)> = Vec::new();
    fn walk(rows: &[PhaseRow], parent: &[String], ordered: &mut Vec<(String, Duration)>) {
        for row in rows
            .iter()
            .filter(|row| row.path.len() == parent.len() + 1 && row.path.starts_with(parent))
        {
            let depth = parent.len();
            let marker = if depth == 0 { "" } else { "- " };
            let times = if row.count > 1 {
                format!(" ({}x)", row.count)
            } else {
                String::new()
            };
            let name = row.path.last().map(String::as_str).unwrap_or_default();
            let label = format!("{}{marker}{name}{times}", "  ".repeat(depth));
            ordered.push((label, row.total));
            walk(rows, &row.path, ordered);
        }
    }
    walk(rows, &[], &mut ordered);
    let timed: Duration = rows
        .iter()
        .filter(|row| row.path.len() == 1)
        .map(|row| row.total)
        .sum();
    if let Some(wall) = wall {
        ordered.push((
            "(outside any phase)".to_string(),
            wall.saturating_sub(timed),
        ));
        ordered.push(("total".to_string(), wall));
    }
    let width = ordered
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0);
    let mut text =
        String::from("phase timings (wall clock; '-' rows are part of the row above them)\n");
    for (label, elapsed) in ordered {
        text.push_str(&format!(
            "  {label:<width$}  {:>9}\n",
            human_duration(elapsed)
        ));
    }
    text
}

/// A duration as a human reads it in a table: milliseconds below a
/// second, seconds above.
fn human_duration(elapsed: Duration) -> String {
    let millis = elapsed.as_secs_f64() * 1000.0;
    if millis < 1000.0 {
        format!("{millis:.1}ms")
    } else {
        format!("{:.2}s", millis / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A child spawned inside the job inherits the redirected descriptor,
    /// and the descriptor is put back afterwards, on the error path too.
    #[test]
    fn a_job_and_its_children_print_to_the_redirected_descriptor() {
        // What a descriptor names, as (device, inode): fd 1 equal before
        // and after means it was put back, not merely that a stdout exists.
        let identity = |fd: i32| {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: fstat writes a full `stat` into the buffer on success.
            assert_eq!(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }, 0);
            // SAFETY: initialized by the successful fstat above.
            let stat = unsafe { stat.assume_init() };
            (stat.st_dev, stat.st_ino)
        };
        let stdout = io::stdout().as_raw_fd();
        let before = identity(stdout);
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_end, write_end) = (fds[0], fds[1]);
        let child = || {
            std::process::Command::new("sh")
                .args(["-c", "echo redirected-marker"])
                .status()
                .map(|_| ())
        };
        with_fd_pointed_at(io::stdout().as_raw_fd(), write_end, child).unwrap();
        let error = with_fd_pointed_at(io::stdout().as_raw_fd(), write_end, || {
            child()?;
            Err::<(), _>(io::Error::other("job failed"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "job failed");
        // Checked before the pipe is drained: a descriptor left pointing at
        // the pipe would hold its write end open and block the read below.
        assert_eq!(identity(stdout), before, "fd 1 was not restored");
        assert_ne!(identity(write_end), before);
        unsafe { libc::close(write_end) };
        let mut captured = String::new();
        // SAFETY: the read end is ours; File takes ownership and closes it.
        let mut reader = unsafe { File::from_raw_fd(read_end) };
        io::Read::read_to_string(&mut reader, &mut captured).unwrap();
        // The test harness writes its own progress to fd 1 meanwhile, so
        // the pipe holds those lines too; the two markers are what matters.
        assert_eq!(
            captured.matches("redirected-marker\n").count(),
            2,
            "{captured}"
        );
    }

    /// A job that panics still gets its descriptor put back, and the saved
    /// copy closed: the guard runs while the panic unwinds. Exercised on a
    /// descriptor of the test's own, so fd 1 of the harness is untouched.
    #[test]
    fn a_panicking_job_still_restores_the_descriptor() {
        let identity = |fd: i32| {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: fstat writes a full `stat` into the buffer on success.
            assert_eq!(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }, 0);
            // SAFETY: initialized by the successful fstat above.
            let stat = unsafe { stat.assume_init() };
            (stat.st_dev, stat.st_ino)
        };
        let swapped = File::open("/dev/null").unwrap();
        let fd = swapped.as_raw_fd();
        let before = identity(fd);
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_end, write_end) = (fds[0], fds[1]);
        let seen = std::panic::catch_unwind(|| {
            with_fd_pointed_at(fd, write_end, || -> io::Result<()> {
                assert_ne!(identity(fd), before, "the job ran unswapped");
                panic!("job panicked");
            })
        });
        assert!(seen.is_err());
        assert_eq!(identity(fd), before, "the descriptor was not restored");
        unsafe {
            libc::close(read_end);
            libc::close(write_end);
        }
    }

    /// Every copy the module makes is close-on-exec from the moment it
    /// exists: no window in which a child forked by another thread could
    /// inherit it.
    #[test]
    fn descriptor_copies_are_close_on_exec() {
        let file = File::open("/dev/null").unwrap();
        let copy = dup_cloexec(file.as_raw_fd()).unwrap();
        // SAFETY: fcntl reads the flags of a descriptor this test owns.
        let flags = unsafe { libc::fcntl(copy, libc::F_GETFD) };
        unsafe { libc::close(copy) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0, "{flags}");
    }

    #[test]
    fn shell_words_quote_only_when_needed() {
        assert_eq!(shell_word("uv"), "uv");
        assert_eq!(shell_word("--python-version=3.12"), "--python-version=3.12");
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("it's"), "'it'\\''s'");
        assert_eq!(shell_word(""), "''");
    }

    #[test]
    fn progress_lines_name_the_artifact_and_scale_the_bytes() {
        assert_eq!(
            progress_line("cpython-3.12.tar.gz", 1024 * 1024, Some(4 * 1024 * 1024)),
            "downloading cpython-3.12.tar.gz  1.0 MiB / 4.0 MiB (25%)"
        );
        // No Content-Length: bytes so far, no percentage to invent.
        assert_eq!(
            progress_line("flask-3.0.0.whl", 2048, None),
            "downloading flask-3.0.0.whl  2.0 KiB"
        );
        // A declared total of zero cannot be divided by.
        assert_eq!(
            progress_line("empty.tar", 0, Some(0)),
            "downloading empty.tar  0 B"
        );
        // Overshoot (a server that under-declares) clamps at 100%.
        assert!(progress_line("x", 30, Some(10)).ends_with("(100%)"));
        // Concurrent downloads share one line: a count and the bytes.
        assert_eq!(
            batch_line(12, 70, 34 * 1024 * 1024 + 200 * 1024),
            "downloading 12/70 artifacts  34.2 MiB"
        );
        assert_eq!(human_bytes(1), "1 B");
        assert_eq!(human_bytes(3 << 30), "3.0 GiB");
    }

    /// Progress is narration on a terminal. Under `cargo test` stderr is a
    /// pipe, so `live` must be false, nothing may be drawn, and no progress
    /// line may be left holding the cursor for the panic hook to clear.
    /// The byte count is kept regardless, because the caller reads it.
    /// `LINE_HELD` is one process-wide flag; the tests that set and read
    /// it take this lock so a parallel one cannot flip it mid-assertion.
    static LINE_HELD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn line_held_lock() -> std::sync::MutexGuard<'static, ()> {
        LINE_HELD_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn progress_is_silent_when_stderr_is_not_a_terminal() {
        let _line = line_held_lock();
        assert!(
            !io::stderr().is_terminal(),
            "the test harness is expected to capture stderr"
        );
        LINE_HELD.store(false, Ordering::Relaxed);
        let mut progress = Progress::start("artifact.tar.gz", Some(10));
        assert!(
            !progress.live,
            "a piped stderr must not get a progress line"
        );
        progress.advance(4);
        progress.advance(6);
        assert!(!progress.drawn, "a piped stderr was drawn to");
        assert!(
            !LINE_HELD.load(Ordering::Relaxed),
            "nothing was drawn, so no line is held"
        );
        assert_eq!(progress.done, 10);
        drop(progress);
        assert!(!LINE_HELD.load(Ordering::Relaxed));
    }

    /// A download on a pool thread reports its bytes to the batch and draws
    /// no line of its own; off a terminal the batch draws nothing either,
    /// and the thread leaves the batch when its job ends.
    #[test]
    fn a_download_inside_a_batch_reports_to_the_batch_line() {
        let _line = line_held_lock();
        LINE_HELD.store(false, Ordering::Relaxed);
        let batch = Batch::start(3);
        let done = in_batch(&batch, || {
            let mut progress = Progress::start("a.tgz", Some(10));
            assert!(!progress.live, "inside a batch the line is the batch's");
            progress.advance(4);
            progress.advance(6);
            progress.done
        });
        batch.finished();
        assert_eq!(done, 10);
        {
            let state = batch.state.lock().unwrap();
            assert_eq!((state.finished, state.bytes, state.drawn), (1, 10, false));
        }
        assert!(!LINE_HELD.load(Ordering::Relaxed));
        assert!(
            Progress::start("b.tgz", None).batch.is_none(),
            "the thread left the batch when the job ended"
        );
    }

    /// The panic hook clears the row a live download is holding, so a crash
    /// mid-transfer does not print onto the tail of the progress line.
    #[test]
    fn a_held_progress_line_is_erased_once() {
        let _line = line_held_lock();
        LINE_HELD.store(true, Ordering::Relaxed);
        erase_progress_line();
        assert!(!LINE_HELD.load(Ordering::Relaxed));
        // Idempotent: the hook and Drop can both run.
        erase_progress_line();
        assert!(!LINE_HELD.load(Ordering::Relaxed));
    }

    #[test]
    fn shell_lines_quote_each_word() {
        assert_eq!(
            shell_line(&["uv", "pip", "install", "a b"]),
            "uv pip install 'a b'"
        );
        assert_eq!(shell_line::<&str>(&[]), "");
    }

    /// Every warning is two lines: what happened, then the one command that
    /// resolves it, with `fix:` right-aligned under `warning:`.
    #[test]
    fn a_warning_is_followed_by_the_command_that_resolves_it() {
        // `init` was never called, so color is off and the text is plain.
        assert!(!color(), "the test process has no terminal");
        assert_eq!(
            warning_lines(
                "node_modules was a real directory; moved aside",
                "ward gc --project"
            ),
            "ward: warning: node_modules was a real directory; moved aside\n\
             ward:     fix: ward gc --project\n"
        );
        assert_eq!(
            WARNING_PREFIX.len(),
            FIX_PREFIX.len(),
            "the two labels must line up"
        );
        assert_eq!(advisory_line("x"), format!("{WARNING_PREFIX}x\n"));
        assert_eq!(
            fix_line("ward --fresh"),
            format!("{FIX_PREFIX}ward --fresh\n")
        );
    }

    /// A warning whose command only explains ends with `next:` instead,
    /// and that command starts in the same column a fix's would.
    #[test]
    fn a_diagnostic_warning_names_the_next_command_in_the_fix_column() {
        assert!(!color(), "the test process has no terminal");
        assert_eq!(
            warning_next_lines("3 policy exception(s) recorded", "ward audit"),
            "ward: warning: 3 policy exception(s) recorded\n\
             ward:    next: ward audit\n"
        );
        assert_eq!(
            NEXT_PREFIX.len(),
            FIX_PREFIX.len(),
            "the command column must line up"
        );
        assert_eq!(
            NEXT_PREFIX.find(": "),
            FIX_PREFIX.find(": "),
            "`next:` right-aligns under `fix:`"
        );
        assert_eq!(
            next_line("ward audit"),
            format!("{NEXT_PREFIX}ward audit\n")
        );
    }

    fn row(path: &[&str], millis: u64, count: u32) -> PhaseRow {
        PhaseRow {
            path: path.iter().map(|part| part.to_string()).collect(),
            total: Duration::from_millis(millis),
            count,
        }
    }

    fn paths(log: &PhaseLog) -> Vec<(Vec<String>, u32)> {
        log.rows()
            .into_iter()
            .map(|row| (row.path, row.count))
            .collect()
    }

    fn owned(path: &[&str]) -> Vec<String> {
        path.iter().map(|part| part.to_string()).collect()
    }

    /// A phase that runs twice is one row with both runs' time in it.
    #[test]
    fn a_phase_accumulates_every_run_into_one_row() {
        let log = PhaseLog::new();
        for _ in 0..2 {
            let _t = log.start("artifact fetch", None);
            std::thread::sleep(Duration::from_millis(5));
        }
        let rows = log.rows();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].count, 2);
        assert!(rows[0].total >= Duration::from_millis(10), "{rows:?}");
    }

    /// A phase opened inside another on the same thread is its child; once
    /// the child drops, the next phase is the parent's sibling again, and
    /// the thread's open path is back to empty when the parent drops.
    #[test]
    fn a_phase_opened_inside_another_is_nested_under_it() {
        let log = PhaseLog::new();
        {
            let _sync = log.start("sync python", None);
            {
                let _t = log.start("toolchain", None);
            }
            let _t = log.start("realize env", None);
        }
        {
            let _t = log.start("notices", None);
        }
        assert_eq!(
            paths(&log),
            vec![
                (owned(&["sync python"]), 1),
                (owned(&["sync python", "toolchain"]), 1),
                (owned(&["sync python", "realize env"]), 1),
                (owned(&["notices"]), 1),
            ]
        );
        assert!(OPEN_PHASE.with(|open| open.borrow().is_empty()));
    }

    /// Threads add to one shared table: a worker that opens its phase under
    /// the caller's (`PhaseParent`) lands as a child with every run
    /// counted, and phases opened on plain threads with no parent are
    /// top-level rows, none lost to a race.
    #[test]
    fn phases_from_many_threads_land_in_one_table() {
        static LOG: PhaseLog = PhaseLog::new();
        let _sync = LOG.start("sync node", None);
        let parent = OPEN_PHASE.with(|open| open.borrow().clone());
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let parent = parent.clone();
                scope.spawn(move || {
                    for _ in 0..25 {
                        let _t = LOG.start("artifact fetch", Some(&parent));
                        // Nested on the worker's own thread, under its
                        // pool phase.
                        let _v = LOG.start("verify", None);
                    }
                    let _t = LOG.start("worker", None);
                });
            }
        });
        drop(_sync);
        assert_eq!(
            paths(&LOG),
            vec![
                (owned(&["sync node"]), 1),
                (owned(&["sync node", "artifact fetch"]), 200),
                (owned(&["sync node", "artifact fetch", "verify"]), 200),
                (owned(&["worker"]), 8),
            ]
        );
    }

    /// The guard does nothing without `--verbose`, and a parent taken then
    /// opens nothing either. The test process never calls `init`.
    #[test]
    fn phases_are_inert_without_verbose() {
        assert!(!verbose(), "the test process never turns on --verbose");
        let guard = phase("input scan");
        assert!(guard.open.is_none());
        assert!(current_phase().phase("artifact fetch").open.is_none());
        drop(guard);
        assert!(PHASES.rows().is_empty());
    }

    #[test]
    fn phases_restore_the_parent_on_error_and_panic() {
        let log = PhaseLog::new();
        let _parent = log.start("sync", None);
        let fail = || -> io::Result<()> {
            let _child = log.start("error", None);
            Err(io::Error::other("failed"))?;
            Ok(())
        };
        assert!(fail().is_err());
        assert!(std::panic::catch_unwind(|| {
            let _child = log.start("panic", None);
            panic!("failed");
        })
        .is_err());
        assert_eq!(
            OPEN_PHASE.with(|open| open.borrow().clone()),
            owned(&["sync"])
        );
        assert_eq!(log.rows()[1].count, 1);
        assert_eq!(log.rows()[2].count, 1);
    }

    #[test]
    fn phases_recover_a_poisoned_table_lock() {
        let log = PhaseLog::new();
        assert!(std::panic::catch_unwind(|| {
            let _lock = log.lock();
            panic!("failed");
        })
        .is_err());
        drop(log.start("sync", None));
        assert_eq!(paths(&log), vec![(owned(&["sync"]), 1)]);
    }

    #[test]
    fn a_closed_timing_output_does_not_panic() {
        let rows = [row(&["preflight"], 12, 1)];
        let mut closed = File::open("/dev/null").unwrap();
        write_phase_table(&rows, None, &mut closed);
        let mut output = Vec::new();
        write_phase_table(&rows, None, &mut output);
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.matches("phase timings").count(), 1);
        assert!(text
            .lines()
            .all(|line| line.starts_with("ward: [verbose] ")));
    }

    /// Top-level rows in start order, each followed by its nested rows,
    /// indented and marked; repeated phases say how often; the gap between
    /// the top-level rows and the wall clock is its own row.
    #[test]
    fn the_table_nests_children_under_their_parent_and_sums_to_the_wall() {
        let rows = vec![
            row(&["preflight"], 12, 1),
            row(&["sync python"], 11_800, 1),
            row(&["sync python", "toolchain"], 8_100, 1),
            row(&["sync python", "realize env"], 3_000, 1),
            row(&["sync python", "realize env", "artifact fetch"], 2_400, 70),
            row(&["notices"], 0, 1),
        ];
        let table = render_phases(&rows, Some(Duration::from_millis(11_900)));
        assert_eq!(
            table,
            "phase timings (wall clock; '-' rows are part of the row above them)\n\
             \x20 preflight                      12.0ms\n\
             \x20 sync python                    11.80s\n\
             \x20   - toolchain                   8.10s\n\
             \x20   - realize env                 3.00s\n\
             \x20     - artifact fetch (70x)      2.40s\n\
             \x20 notices                         0.0ms\n\
             \x20 (outside any phase)            88.0ms\n\
             \x20 total                          11.90s\n"
        );
        // No wall clock (verbose was never set): no summary rows.
        let table = render_phases(&rows[..1], None);
        assert_eq!(
            table.lines().nth(1),
            Some("  preflight     12.0ms"),
            "{table}"
        );
        assert_eq!(table.lines().count(), 2, "{table}");
    }
}
