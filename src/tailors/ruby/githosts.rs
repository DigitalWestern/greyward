//! The hosts a Gemfile's git sources name, read from its text without
//! evaluating it. A Gemfile is Ruby, so this tokenizes it (comments,
//! `=begin` blocks, `__END__`, heredoc bodies and the contents of strings
//! that are not a source are dropped) and reads only literal git source
//! declarations: a `git:` option, a `git "..." do` block, the `github:`,
//! `gitlab:`, `gist:` and `bitbucket:` shorthands (options or blocks), and
//! the remotes a `git_source` block body writes. A Bundler run that writes
//! the lock gets git fetches through the resolution proxy to these hosts
//! and to no other (`Intercept::Git`). A remote the scan cannot read (one
//! whose host is built by interpolation or a variable, or one named in a
//! file `eval_gemfile` loads) is refused, naming the host, unless another
//! declaration named that host.

/// The host each shorthand option fetches from, as Bundler's built-in
/// `git_source`s define them.
const SHORTHANDS: &[(&str, &str)] = &[
    ("github", "github.com"),
    ("gitlab", "gitlab.com"),
    ("gist", "gist.github.com"),
    ("bitbucket", "bitbucket.org"),
];

/// Words after which an operator-looking character starts a literal.
const KEYWORDS: &[&str] = &[
    "and", "do", "else", "elsif", "if", "in", "not", "or", "return", "then", "unless", "until",
    "when", "while",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// An identifier, keyword, or `@`/`$` variable.
    Ident(String),
    /// A hash key written `name:` or `"name":`.
    Label(String),
    /// `:name` or `:"name"`.
    Sym(String),
    /// A string literal's raw contents (`#{...}` kept as written).
    Str(String),
    /// A literal that is a value but no string ward reads: a number, a
    /// heredoc, `%w[...]`, a regexp, a character.
    Lit,
    Arrow,
    Punct(char),
    Newline,
}

/// The hosts `gemfile`'s git sources fetch from, lowercase, with the port
/// when it is not 443, sorted, each once.
pub(super) fn git_hosts(gemfile: &str) -> Vec<String> {
    let toks = Lexer::new(gemfile).run();
    let mut hosts = Vec::new();
    for (at, tok) in toks.iter().enumerate() {
        let Tok::Ident(name) = tok else { continue };
        if at > 0 && toks[at - 1] == Tok::Punct('.') {
            continue;
        }
        if name == "gem" {
            hosts.extend(gem_options(&toks[at + 1..]));
        }
        // `git "https://host/repo.git" do`, `github("org/repo") do`
        let mut value = at + 1;
        if toks.get(value) == Some(&Tok::Punct('(')) {
            value += 1;
        }
        if let Some(Tok::Str(text)) = toks.get(value) {
            hosts.extend(source_host(name, text));
        }
        if name == "git_source" {
            hosts.extend(block_strings(&toks[at + 1..]).filter_map(host_of));
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Literal source options in one `gem` call. Unrelated hashes and other
/// calls do not grant network access. Parentheses and hash literals may
/// span lines; an unparenthesized call continues after a comma.
fn gem_options(toks: &[Tok]) -> Vec<String> {
    let mut hosts = Vec::new();
    let mut depth = 0usize;
    for (at, tok) in toks.iter().enumerate() {
        match tok {
            Tok::Punct('(' | '[' | '{') => depth += 1,
            Tok::Punct(')' | ']' | '}') => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
                if depth == 0 && toks.first() == Some(&Tok::Punct('(')) {
                    break;
                }
            }
            Tok::Punct(';') if depth == 0 => break,
            Tok::Newline if depth == 0 && at > 0 && toks[at - 1] != Tok::Punct(',') => {
                break;
            }
            Tok::Ident(word) if depth == 0 && word == "do" => break,
            _ => {}
        }
        let option = match tok {
            Tok::Label(key) => Some((key, at + 1)),
            Tok::Sym(key) | Tok::Str(key) if toks.get(at + 1) == Some(&Tok::Arrow) => {
                Some((key, at + 2))
            }
            _ => None,
        };
        if let Some((key, Some(Tok::Str(value)))) = option.map(|(key, v)| (key, toks.get(v))) {
            hosts.extend(source_host(key, value));
        }
    }
    hosts
}

/// The host a `key` option or block with the literal `value` fetches from.
fn source_host(key: &str, value: &str) -> Option<String> {
    if key == "git" {
        return host_of(value);
    }
    let (_, host) = SHORTHANDS.iter().find(|(name, _)| *name == key)?;
    (!value.is_empty()).then(|| host.to_string())
}

/// The strings in the block that follows a `git_source(:name)`: a `{ }`
/// block, or a `do ... end` one up to its first `end` that closes no inner
/// `do` (an inner `if ... end` ends it early, so a remote past it is not
/// read).
fn block_strings(toks: &[Tok]) -> impl Iterator<Item = &str> {
    let open = toks
        .iter()
        .take_while(|tok| **tok != Tok::Newline)
        .position(|tok| matches!(tok, Tok::Punct('{')) || *tok == Tok::Ident("do".into()));
    let mut depth = 0usize;
    let mut body = &toks[..0];
    if let Some(open) = open {
        let brace = toks[open] == Tok::Punct('{');
        let end = toks[open..].iter().position(|tok| {
            let (opens, closes) = match brace {
                true => (Tok::Punct('{'), Tok::Punct('}')),
                false => (Tok::Ident("do".into()), Tok::Ident("end".into())),
            };
            if *tok == opens {
                depth += 1;
            } else if *tok == closes {
                depth -= 1;
                return depth == 0;
            }
            false
        });
        body = &toks[open..open + end.unwrap_or(toks.len() - open)];
    }
    body.iter().filter_map(|tok| match tok {
        Tok::Str(text) => Some(text.as_str()),
        _ => None,
    })
}

/// Ruby tokens, as far as finding git sources needs them.
struct Lexer {
    chars: Vec<char>,
    at: usize,
    toks: Vec<Tok>,
    /// Heredoc terminators opened on the current line, and whether each
    /// may be indented (`<<~` and `<<-`).
    heredocs: Vec<(String, bool)>,
    /// Whether whitespace came right before the current character.
    spaced: bool,
}

impl Lexer {
    fn new(text: &str) -> Self {
        Lexer {
            chars: text.chars().collect(),
            at: 0,
            toks: Vec::new(),
            heredocs: Vec::new(),
            spaced: false,
        }
    }

    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    /// The rest of the current line, from `at`.
    fn line(&self) -> String {
        self.chars[self.at..]
            .iter()
            .take_while(|c| **c != '\n')
            .collect()
    }

    /// Move past the end of the current line.
    fn skip_line(&mut self) {
        while let Some(c) = self.peek(0) {
            self.at += 1;
            if c == '\n' {
                break;
            }
        }
    }

    /// Whether the last token is a value, after which `/`, `%`, `?` and
    /// `<<` are operators rather than the start of a literal.
    fn after_value(&self) -> bool {
        match self.toks.last() {
            Some(Tok::Ident(word)) => !KEYWORDS.contains(&word.as_str()),
            Some(Tok::Str(_) | Tok::Sym(_) | Tok::Lit) => true,
            Some(Tok::Punct(c)) => matches!(c, ')' | ']' | '}'),
            _ => false,
        }
    }

    /// Whether an operator-looking character here starts a literal: after
    /// no value, or (`foo %w[a]`) after a space and before none.
    fn starts_literal(&self) -> bool {
        !self.after_value() || (self.spaced && self.peek(1).is_some_and(|c| !c.is_whitespace()))
    }

    fn run(mut self) -> Vec<Tok> {
        let mut line_start = true;
        while let Some(c) = self.peek(0) {
            if line_start {
                line_start = false;
                let line = self.line();
                if line.trim_end() == "__END__" {
                    break;
                }
                if comment_marker(&line, "=begin") {
                    while self.peek(0).is_some() && !comment_marker(&self.line(), "=end") {
                        self.skip_line();
                    }
                    self.skip_line();
                    line_start = true;
                    continue;
                }
            }
            let spaced = c.is_whitespace() && c != '\n';
            if c == '\n' {
                self.at += 1;
                self.toks.push(Tok::Newline);
                self.skip_heredoc_bodies();
                line_start = true;
            } else if spaced || (c == '\\' && self.peek(1) == Some('\n')) {
                self.at += if spaced { 1 } else { 2 };
            } else if c == '#' {
                while self.peek(0).is_some_and(|c| c != '\n') {
                    self.at += 1;
                }
            } else {
                self.token(c);
            }
            self.spaced = spaced;
        }
        self.toks
    }

    /// One token starting at `c`, which is not whitespace or a comment.
    fn token(&mut self, c: char) {
        let next = self.peek(1);
        if (c == '%' && self.starts_literal() && self.percent())
            || (c == '<' && next == Some('<') && self.heredoc())
        {
            return;
        }
        if c == '"' || c == '\'' || c == '`' {
            self.at += 1;
            let text = self.quoted(c);
            self.labelled(text, c == '`');
        } else if c == ':' && next == Some(':') {
            self.at += 2;
            self.toks.push(Tok::Punct(':'));
        } else if c == ':' && matches!(next, Some('"' | '\'')) {
            self.at += 2;
            let text = self.quoted(next.unwrap_or('"'));
            self.toks.push(Tok::Sym(text));
        } else if c == ':' && next.is_some_and(is_word) {
            self.at += 1;
            let word = self.word();
            self.toks.push(Tok::Sym(word));
        } else if c == '=' && next == Some('>') {
            self.at += 2;
            self.toks.push(Tok::Arrow);
        } else if c == '/' && self.starts_literal() {
            self.at += 1;
            self.quoted('/');
            self.toks.push(Tok::Lit);
        } else if c == '?' && !self.after_value() && next.is_some_and(|c| !c.is_whitespace()) {
            self.at += 2;
            self.toks.push(Tok::Lit);
        } else if c.is_ascii_digit() {
            while self
                .peek(0)
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
            {
                self.at += 1;
            }
            self.toks.push(Tok::Lit);
        } else if is_word(c) || c == '@' || c == '$' {
            self.at += 1;
            let word = format!("{c}{}", self.word());
            if self.peek(0) == Some(':') && self.peek(1) != Some(':') {
                self.at += 1;
                self.toks.push(Tok::Label(word));
            } else {
                self.toks.push(Tok::Ident(word));
            }
        } else {
            self.at += 1;
            self.toks.push(Tok::Punct(c));
        }
    }

    /// A string just read: a label when a `:` follows it directly (and not
    /// `::`), a string otherwise. A backtick command is no string.
    fn labelled(&mut self, text: String, command: bool) {
        if !command && self.peek(0) == Some(':') && self.peek(1) != Some(':') {
            self.at += 1;
            self.toks.push(Tok::Label(text));
        } else if command {
            self.toks.push(Tok::Lit);
        } else {
            self.toks.push(Tok::Str(text));
        }
    }

    /// Identifier characters from `at`, with a trailing `?` or `!`.
    fn word(&mut self) -> String {
        let mut word = String::new();
        while let Some(c) = self.peek(0).filter(|c| is_word(*c) || c.is_ascii_digit()) {
            word.push(c);
            self.at += 1;
        }
        if let Some(c) = self.peek(0).filter(|c| matches!(c, '?' | '!')) {
            if self.peek(1) != Some('=') {
                word.push(c);
                self.at += 1;
            }
        }
        word
    }

    /// The contents of a literal whose opening delimiter is behind `at`, up
    /// to the unescaped `close`, nesting `open` (for `%q(...)` and the like)
    /// and `#{...}` (whose own strings are skipped whole).
    fn delimited(&mut self, open: Option<char>, close: char) -> String {
        let mut text = String::new();
        let mut depth = 0usize;
        while let Some(c) = self.peek(0) {
            self.at += 1;
            if c == '\\' {
                text.push(c);
                text.extend(self.peek(0));
                self.at += 1;
            } else if c == '#' && self.peek(0) == Some('{') {
                self.at += 1;
                text.push_str("#{");
                text.push_str(&self.delimited(Some('{'), '}'));
                text.push('}');
            } else if Some(c) == open && open != Some(close) {
                depth += 1;
                text.push(c);
            } else if c == close && depth > 0 {
                depth -= 1;
                text.push(c);
            } else if c == close {
                break;
            } else if open == Some('{') && matches!(c, '"' | '\'') {
                text.push(c);
                text.push_str(&self.quoted(c));
                text.push(c);
            } else {
                text.push(c);
            }
        }
        text
    }

    fn quoted(&mut self, quote: char) -> String {
        self.delimited(None, quote)
    }

    /// A `%` literal at `at`: `%q(...)`, `%Q[...]` and `%(...)` are strings,
    /// the other kinds are values ward does not read. `false` when `%` is
    /// the operator.
    fn percent(&mut self) -> bool {
        let (kind, delimiter) = match (self.peek(1), self.peek(2)) {
            (Some(k), Some(d)) if "qQwWiIrsx".contains(k) && !d.is_alphanumeric() => (Some(k), d),
            (Some(d), _) if "([{<|!/^".contains(d) => (None, d),
            _ => return false,
        };
        if delimiter.is_whitespace() {
            return false;
        }
        self.at += if kind.is_some() { 3 } else { 2 };
        let close = match delimiter {
            '(' => ')',
            '[' => ']',
            '{' => '}',
            '<' => '>',
            other => other,
        };
        let text = self.delimited(Some(delimiter), close);
        self.toks.push(match kind {
            None | Some('q' | 'Q') => Tok::Str(text),
            Some(_) => Tok::Lit,
        });
        true
    }

    /// A heredoc opener at `at` (`<<~ID`, `<<-ID`, `<<ID`, any of them
    /// quoted): its body, from the next line to the terminator, is skipped
    /// there. `false` when `<<` is the operator.
    fn heredoc(&mut self) -> bool {
        let mut ahead = 2;
        let indented = matches!(self.peek(ahead), Some('~' | '-'));
        if indented {
            ahead += 1;
        }
        let quote = self.peek(ahead).filter(|c| matches!(c, '\'' | '"' | '`'));
        if quote.is_some() {
            ahead += 1;
        }
        let starts = self
            .peek(ahead)
            .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
            || (quote.is_some() && self.peek(ahead).is_some_and(is_word));
        if !starts || (self.after_value() && !indented && !self.spaced) {
            return false;
        }
        self.at += ahead;
        let mut id = String::new();
        while let Some(c) = self.peek(0).filter(|c| is_word(*c) || c.is_ascii_digit()) {
            id.push(c);
            self.at += 1;
        }
        if quote.is_some() && self.peek(0) == quote {
            self.at += 1;
        }
        self.heredocs.push((id, indented));
        self.toks.push(Tok::Lit);
        true
    }

    /// After a newline: the bodies of the heredocs the line opened.
    fn skip_heredoc_bodies(&mut self) {
        for (id, indented) in std::mem::take(&mut self.heredocs) {
            while self.peek(0).is_some() {
                let line = self.line();
                self.skip_line();
                let line = if indented {
                    line.trim()
                } else {
                    line.trim_end()
                };
                if line == id {
                    break;
                }
            }
        }
    }
}

fn is_word(c: char) -> bool {
    c.is_alphabetic() || c == '_' || !c.is_ascii()
}

fn comment_marker(line: &str, marker: &str) -> bool {
    line.strip_prefix(marker)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
}

/// The host `remote` fetches from over https, as the git row reaches it:
/// an `https://` URL's host, with its port when that is not 443, or an ssh
/// remote's (`ssh://` or `git@host:path`), which the git row rewrites to
/// https on 443. `None` for anything else (`http://` and `git://` are
/// refused, a local path needs no network) and for a host built by
/// interpolation.
fn host_of(remote: &str) -> Option<String> {
    let (rest, https, scp) = if let Some(rest) = remote.strip_prefix("https://") {
        (rest, true, false)
    } else if let Some(rest) = remote.strip_prefix("ssh://") {
        (rest, false, false)
    } else {
        (remote.strip_prefix("git@")?, false, true)
    };
    let authority = match scp {
        true => rest.split(':').next()?,
        // Keep `#{...}` in the authority so validation refuses an
        // interpolated host rather than authorizing its literal prefix.
        false => rest.split(['/', '?']).next()?,
    };
    let authority = authority.rsplit('@').next()?;
    let (host, port) = match scp {
        true => (authority, None),
        false => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    let host = host.to_ascii_lowercase();
    let plain = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if !plain || host.is_empty() || host.starts_with(['.', '-']) {
        return None;
    }
    match port.filter(|_| https) {
        None => Some(host),
        Some(port) => {
            let number: u16 = port.parse().ok().filter(|n| *n != 0)?;
            Some(match number {
                443 => host,
                _ => format!("{host}:{number}"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every place Bundler takes a git remote from is read, in each
    /// spelling; a `source`, and a remote that is not https (or an ssh one
    /// the git row rewrites to https) add nothing. A port other than 443
    /// is kept, so the proxy admits that port alone.
    #[test]
    fn git_hosts_are_read_from_every_git_option() {
        let gemfile = r#"source "https://rubygems.org"
gem "xpath", git: "https://github.com/teamcapybara/xpath.git"
gem "spec", :git => 'https://GitLab.com/a/spec.git', branch: "main"
gem "quoted", "git" => "https://quoted.example/q.git"
gem "labelled", "git": "https://labelled.example/l.git"
gem "short", github: "rails/rails"
gem "lab", gitlab: "org/lab"
gem "gist", gist: "abc123"
gem "bb", :bitbucket => "team/bb"
gem "scp", git: "git@codeberg.org:me/scp.git"
gem "ssh", git: "ssh://git@ssh.example:2222/me/ssh.git"
gem "plain", git: "http://insecure.example/x.git"
gem "daemon", git: "git://daemon.example/x.git"
gem "local", git: "/srv/repos/local"
gem "built", git: "https://#{ENV["HOST"]}/x.git"
gem "suffix", git: "https://prefix#{ENV["SUFFIX"]}/x.git"
gem "domain", git: "https://git.#{ENV["DOMAIN"]}/x.git"
gem "port", git: "https://ported.example:8443/x.git"
gem "default", git: "https://default.example:443/x.git"
gem("paren", { git: %q(https://percent.example/p.git) })
gem "rails", "~> 8.0", require: "digit: 'not-a-key'"
git "https://block.example/mono.git" do
  gem "member"
end
github("org/mono") do
  gem "hubbed"
end
git_source(:internal) { |repo| "https://git.internal.example/#{repo}.git" }
git_source(:other) do |repo|
  "https://other.example/#{repo}"
end
gem "custom", internal: "team/custom"
"#;
        assert_eq!(
            git_hosts(gemfile),
            [
                "bitbucket.org",
                "block.example",
                "codeberg.org",
                "default.example",
                "gist.github.com",
                "git.internal.example",
                "github.com",
                "gitlab.com",
                "labelled.example",
                "other.example",
                "percent.example",
                "ported.example:8443",
                "quoted.example",
                "ssh.example",
            ]
        );
    }

    /// A Gemfile with no git source opens no git route.
    #[test]
    fn a_gemfile_without_git_sources_names_no_host() {
        let gemfile = "source \"https://rubygems.org\"\ngemspec\ngem \"rake\"\n\
                       gem \"github_api\", \">= 1\"\ngem \"x\", path: \"vendor/x\"\n";
        assert!(git_hosts(gemfile).is_empty());
    }

    /// Text that only looks like a git source names no host: a comment
    /// (whole-line or trailing), a `=begin` block, the contents of a
    /// string, a `%` literal or a heredoc, a method called on an object,
    /// and anything after `__END__`.
    #[test]
    fn comments_strings_and_heredocs_name_no_host() {
        let gemfile = r#"source "https://rubygems.org"
# gem "commented", git: "https://commented.example/x.git"
gem "rake" # git: "https://comment.example/x.git"
gem "said", require: "git: 'https://string.example/x.git'"
NOTE = %q{git: "https://percent.example/x.git"}
LIST = %w[git: https://words.example/x.git]
OPTIONS = { git: "https://hash.example/x.git" }
config(git: "https://argument.example/x.git")
=begin
gem "blocked", git: "https://begin.example/x.git"
=endless
gem "still-blocked", git: "https://endless.example/x.git"
git "https://begin-block.example/x.git" do end
=end
README = <<~TEXT
  gem "doc", git: "https://heredoc.example/x.git"
  github: "org/repo"
TEXT
DASHED = <<-'RAW'
  git "https://dashed.example/x.git" do
  RAW
config.git "https://method.example/x.git"
x = 1 / 2 # git: "https://division.example/x.git"
y = 10 % 3 # git: "https://modulo.example/x.git"
gem "after", "~> 1.0"
__END__
gem "end", git: "https://end.example/x.git"
"#;
        assert!(git_hosts(gemfile).is_empty(), "{:?}", git_hosts(gemfile));
    }

    /// A git source after a heredoc or a `=begin` block is still read: the
    /// tokenizer resumes where they end.
    #[test]
    fn sources_after_skipped_text_are_read() {
        let gemfile = "TEXT = <<~EOS\n  \"unterminated\n  EOS\n\
                       =begin\nnothing\n=end\n\
                       gem \"x\", git: \"https://after.example/x.git\" # trailing\n";
        assert_eq!(git_hosts(gemfile), ["after.example"]);
    }

    #[test]
    fn multiline_gem_options_are_read_within_that_call() {
        let gemfile = "gem \"x\",\n  git: \"https://comma.example/x.git\"\n\
                       gem(\"y\",\n  git: \"https://paren.example/y.git\")\n\
                       gem \"z\", {\n  git: \"https://hash.example/z.git\"\n}\n\
                       note = { git: \"https://unrelated.example/x.git\" }\n";
        assert_eq!(
            git_hosts(gemfile),
            ["comma.example", "hash.example", "paren.example"]
        );
    }
}
