//! The Ruby script ward runs with the pinned Ruby and Bundler: it reads
//! the lock, installs gems and git checkouts, and reads gem specs.
//! `kernel::resolve::tripwire::RUBY_HELPER_SHA256` pins its text.

/// Helper executed BY the pinned Ruby: parses the lock with Bundler's own
/// classes, validates the Gemfile/ruby directive, selects the local
/// platform's closure, and emits it dependency-first as JSON.
/// Extra modes install gems, check manifests, and read a downloaded .gem's
/// spec for post-download checks.
pub(super) const HELPER: &str = r##"
require "json"
mode = ARGV.shift
# The Bundler the lock was written with, when ward provisioned one newer
# than this Ruby's own: it is on GEM_PATH, and is activated by its exact
# version before anything requires Bundler, so no other one can load.
activate_bundler = lambda do
  pinned = ENV["WARD_BUNDLER_VERSION"].to_s
  gem "bundler", "= #{pinned}" unless pinned.empty?
end
# ward's native library set, when given: mkmf takes the flags its
# Makefile uses from extconf's arguments, never from the environment, and
# each one replaces Ruby's own default, so the default leads.
native_build_args = lambda do |native_libs|
  build_args = []
  if native_libs && !native_libs.empty?
    require "rbconfig"
    require "shellwords"
    include = Shellwords.escape(File.join(native_libs, "include"))
    lib = Shellwords.escape(File.join(native_libs, "lib"))
    build_args << "--with-cppflags=#{RbConfig::CONFIG["CPPFLAGS"]} -I#{include}"
    build_args << "--with-ldflags=#{RbConfig::CONFIG["LDFLAGS"]} -L#{lib} -Wl,-rpath,#{lib}"
  end
  build_args
end
# git's settings for the throwaway repositories below: no host or user
# configuration, no prompt, and a fixed identity and date.
index_env = {
  "GIT_CONFIG_NOSYSTEM" => "1", "GIT_CONFIG_GLOBAL" => File::NULL,
  "GIT_TERMINAL_PROMPT" => "0",
  "GIT_AUTHOR_NAME" => "ward", "GIT_AUTHOR_EMAIL" => "ward@invalid",
  "GIT_AUTHOR_DATE" => "1970-01-01T00:00:00Z",
  "GIT_COMMITTER_NAME" => "ward", "GIT_COMMITTER_EMAIL" => "ward@invalid",
  "GIT_COMMITTER_DATE" => "1970-01-01T00:00:00Z"
}
# And on the command line, after the sandbox's own: no automatic
# maintenance, which git (2.47 on) starts detached after a commit, where it
# would write into the repository after the helper removed it.
index_config = ["-c", "init.defaultBranch=ward", "-c", "commit.gpgsign=false",
                "-c", "maintenance.auto=false", "-c", "gc.auto=0"]
# Runs `work` over ward's copy of the project with a throwaway git index of
# it. Bundler evaluates the project's gemspecs, and a gemspec commonly
# lists its files with `git ls-files`; the copy has no git data, so the
# index (no template, so no host hooks) answers those calls. It is removed
# when `work` ends, and never published. Without git, `work` runs as it
# would have: the gemspec's own call fails the same way.
with_index = lambda do |work|
  require "fileutils"
  git_dir = File.join(Dir.pwd, ".git")
  made = !(File.exist?(git_dir) || File.symlink?(git_dir))
  if made
    quiet = { out: File::NULL, err: File::NULL }
    indexed = system(index_env, "git", *index_config, "init", "-q", "--template=", **quiet) &&
              system(index_env, "git", *index_config, "add", "-A", **quiet)
    FileUtils.rm_rf(git_dir) unless indexed
  end
  begin
    work.call
  ensure
    FileUtils.rm_rf(git_dir) if made
  end
end
if mode == "indexed"
  # `bundle <args>`, over the throwaway index.
  require "rbconfig"
  abort "usage: helper indexed bundle <args>" unless ARGV.shift == "bundle"
  bundle = File.join(RbConfig::CONFIG["bindir"], "bundle")
  ok = with_index.call(-> { system(RbConfig.ruby, "-x", bundle, *ARGV) })
  exit(ok ? 0 : ($?.exitstatus || 1))
end
if mode == "remove"
  # Bundler's editor evaluates gemspecs too. Activate the same exact
  # Bundler as the later lock run and give them the project index.
  activate_bundler.call
  require "bundler"
  require "bundler/injector"
  abort "no gems requested" if ARGV.empty?
  with_index.call(-> { Bundler::Injector.remove(ARGV) })
  exit 0
end
if mode == "install"
  # Direct Gem::Installer: the `gem install` CLI requires remote_fetcher at
  # LOAD time, which trips EPERM under the network-denied sandbox. This
  # path is offline-only code. wrappers: real wrapper scripts, NEVER
  # symlinks — symlink binstubs point into the staging dir and dangle
  # after the store commit rename (Sol review, reproduced).
  require "rubygems/installer"
  gemfile, install_dir, native_libs = ARGV
  build_args = native_build_args.call(native_libs)
  installer = Gem::Installer.at(
    gemfile,
    install_dir: install_dir,
    bin_dir: File.join(install_dir, "bin"),
    ignore_dependencies: true,
    document: [],
    wrappers: true,
    env_shebang: true,
    build_args: build_args
  )
  installer.install
  puts "installed #{File.basename(gemfile)}"
  exit 0
end
if mode == "check"
  # Gemfile/lock equivalence + ruby-version gate. This mode EVALS THE
  # GEMFILE (arbitrary ruby, delegated resolver trust): its stdout is
  # never parsed by ward — only the exit status counts, so a hostile
  # Gemfile cannot forge plan data through this process. Its gemspecs see
  # the throwaway index, as when the lock was written.
  activate_bundler.call
  require "bundler"
  gemfile, lockfile = ARGV
  with_index.call(lambda do
    definition = Bundler::Definition.build(Pathname.new(gemfile), Pathname.new(lockfile), false)
    begin
      definition.send(:ensure_equivalent_gemfile_and_lockfile)
    rescue NoMethodError
      abort "store bundler cannot validate gemfile/lock equivalence"
    end
    begin
      definition.validate_runtime!
    rescue Bundler::GemNotFound, Bundler::SolveFailure
    rescue NotImplementedError, NoMethodError
    end
  end)
  exit 0
end
if mode == "spec"
  require "rubygems/package"
  spec = Gem::Package.new(ARGV[0]).spec
  puts({ "name" => spec.name, "version" => spec.version.to_s,
         "platform" => spec.platform.to_s,
         "executables" => spec.executables,
         "extensions" => spec.extensions }.to_json)
  exit 0
end
if mode == "git-install"
  # One checkout's gems, installed the way `bundle install` installs them
  # once the checkout is in place: ward fetched the locked commit and
  # copied its tree to <GEM_HOME>/bundler/gems/<checkout> before this
  # runs, so Bundler finds it checked out and fetches nothing. Several
  # lock sources can name the one directory (a glob each, or a mirror's
  # URL); each is installed from the one copy. Bundler's own installer
  # evaluates and serializes the gemspecs, compiles native extensions
  # where Bundler looks for them at run time, and writes the executables'
  # wrappers. Offline: nothing here fetches.
  activate_bundler.call
  require "bundler"
  require "fileutils"
  native_libs, revision, checkout, report, sources = ARGV
  report = File.expand_path(report)
  build_args = native_build_args.call(native_libs)
  root = File.join(ENV.fetch("GEM_HOME"), "bundler", "gems", checkout)
  # A gemspec commonly lists its files with `git ls-files`, and Bundler
  # evaluates it inside a git checkout. ward's copy has no git data, so a
  # throwaway repository indexes the tree the commit tracked; it is
  # removed before ward commits the gems object.
  git_dir = File.join(root, ".git")
  if File.exist?(git_dir) || File.symlink?(git_dir)
    abort "#{checkout}: the checkout already has git data"
  end
  git = lambda do |*args|
    ok = system(index_env, "git", *index_config, *args, chdir: root, out: File::NULL)
    abort "#{checkout}: git #{args.first} failed while indexing the checkout for its gemspecs" unless ok
  end
  executables = {}
  begin
    # No template: a host template's hooks would run at the commit
    # (`--no-verify` does not stop post-commit), as gitsrc's init does.
    git.call("init", "-q", "--template=")
    git.call("add", "-A", "-f")
    git.call("commit", "-q", "--allow-empty", "--no-verify", "-m", revision)
    JSON.parse(sources).each do |source|
      uri, glob, wanted = source.values_at("uri", "glob", "gems")
      options = { "uri" => uri, "revision" => revision }
      options["glob"] = glob unless glob.empty?
      src = Bundler::Source::Git.new(options)
      unless src.install_path.to_s == root
        abort "bundler expects #{uri} at #{src.install_path}, not #{root}"
      end
      src.send(:serialize_gemspecs_in, src.install_path)
      specs = src.local_specs
      wanted.each do |coordinate|
        name, version = coordinate.split(":", 2)
        spec = specs.search(name).find { |s| s.version.to_s == version }
        abort "#{name} #{version}: no such gemspec in #{uri} at #{revision}" unless spec
        # What `Source::Git#install` does once the checkout is in place,
        # without its "Using ... from" line: that line names the branch,
        # which asks git about the repository ward fetched from.
        src.send(:generate_bin, spec,
                  disable_extensions: !spec.missing_extensions?, build_args: build_args)
        executables[name] = spec.executables
        puts "installed #{name}-#{version} from #{checkout}"
      end
    end
  ensure
    FileUtils.rm_rf(git_dir)
  end
  # The executables, for ward to check against the plan's other gems.
  File.write(report, { "executables" => executables }.to_json)
  exit 0
end
abort "usage: helper plan <lockfile>" unless mode == "plan"
# LOCK-ONLY: this mode never evaluates the Gemfile (arbitrary ruby must
# not be able to forge artifact coordinates); the lockfile is the sole
# artifact authority (Sol review, forged-JSON repro).
activate_bundler.call
require "bundler"
lockfile = ARGV[0]
lock = Bundler::LockfileParser.new(File.read(lockfile))
unless (lock.bundler_version rescue nil).nil?
  if Gem::Version.new(lock.bundler_version.to_s) > Gem::Version.new(Bundler::VERSION)
    abort "lockfile BUNDLED WITH #{lock.bundler_version} is newer than the store bundler #{Bundler::VERSION}"
  end
end
require "uri"
# Where each spec comes from: rubygems.org (downloaded and verified), a
# PATH source (the project's own gems, which Bundler loads from the
# checkout), or a GIT source (fetched at its locked revision). Git is a
# subclass of Path, so it is asked first.
source_kind = lambda do |src|
  if src.is_a?(Bundler::Source::Git)
    :git
  elsif src.is_a?(Bundler::Source::Path)
    :path
  elsif src.is_a?(Bundler::Source::Rubygems) && src.remotes.all? { |r|
          u = URI.parse(r.to_s)
          u.scheme == "https" && u.host == "rubygems.org" && u.userinfo.nil? &&
            (u.port == 443) && ["", "/"].include?(u.path)
        }
    :gem
  end
end
lock.specs.each do |s|
  next if source_kind.call(s.source)
  abort "unsupported source for #{s.name} (#{s.source.class}); only https://rubygems.org, path and git sources are supported"
end
local = Gem::Platform.local
# Bundler 4 moved its platform scoring from GemHelpers to MatchPlatform.
platform_match =
  if Bundler.const_defined?(:MatchPlatform) &&
     Bundler::MatchPlatform.respond_to?(:select_best_platform_match)
    Bundler::MatchPlatform
  else
    Bundler::GemHelpers
  end
selected = lock.specs.group_by(&:name).map do |name, specs|
  # Bundler's OWN best-platform scoring (arm64-darwin vs arm64-darwin-20
  # etc.); hand-rolled specificity picks the wrong artifact.
  best = platform_match.select_best_platform_match(specs, local)
  best = Array(best)
  abort "#{name}: no variant for #{local} (have: #{specs.map { |s| s.platform.to_s }.uniq.join(", ")}); run: bundle lock --add-platform #{local}" if best.empty?
  best.first
end
# Bundler's parsed checksums: each rubygems source keeps the lock's
# entries in its checksum store, which writes a spec's entry back in the
# lock's own form (`name (version) sha256=<hex>`, Bundler 2.5 through 4).
# If a CHECKSUMS section exists but yields no usable sha256 for a
# selected gem, fail CLOSED rather than falling back to the live API.
has_checksums_section = File.read(lockfile).lines.any? { |l| l.chomp == "CHECKSUMS" }
checksums = {}
if has_checksums_section
  selected.each do |s|
    # Bundler writes no checksum for a path or git gem: there is no
    # package file to digest.
    next unless source_kind.call(s.source) == :gem
    entry = (s.source.checksum_store.to_lock(s) rescue nil).to_s
    hexval = entry[/[\s,]sha256=([0-9a-f]{64})(?:,|\z)/, 1]
    abort "#{s.name}: CHECKSUMS section present but no usable sha256 for #{s.name}-#{s.version}; refusing API fallback" if hexval.nil?
    plat = s.platform.to_s
    checksums["#{s.name}-#{s.version}#{plat == "ruby" ? "" : "-#{plat}"}"] = hexval
  end
end
by_name = selected.to_h { |s| [s.name, s] }
ordered = []
state = {}
visit = lambda do |s|
  case state[s.name]
  when :done then next
  when :visiting then next # cycle: break arbitrarily, install order best-effort
  end
  state[s.name] = :visiting
  s.dependencies.each do |d|
    dep = by_name[d.name]
    visit.call(dep) if dep
  end
  state[s.name] = :done
  ordered << s
end
selected.each { |s| visit.call(s) }
out = []
path_out = []
git_out = []
ordered.each do |s|
  src = s.source
  case source_kind.call(src)
  when :gem
    plat = s.platform.to_s
    full = plat == "ruby" ? "#{s.name}-#{s.version}" : "#{s.name}-#{s.version}-#{plat}"
    out << { "name" => s.name, "version" => s.version.to_s, "platform" => plat,
             "full_name" => full,
             "checksum" => checksums["#{s.name}-#{s.version}#{plat == "ruby" ? "" : "-#{plat}"}"] }
  when :path
    # The `remote:` the lock names, as written: ward checks it stays
    # inside the project.
    path_out << { "name" => s.name, "version" => s.version.to_s,
                  "path" => src.options["path"].to_s }
  when :git
    revision = src.options["revision"].to_s
    # Where Bundler looks for this checkout at run time:
    # <GEM_HOME>/bundler/gems/<checkout>, named by Bundler's own rule.
    checkout = "#{src.send(:base_name)}-#{src.send(:shortref_for_path, revision)}"
    glob = src.options["glob"].to_s
    git_out << { "name" => s.name, "version" => s.version.to_s,
                 "url" => src.uri.to_s, "revision" => revision,
                 "checkout" => checkout, "glob" => glob,
                 "submodules" => !!src.submodules }
  end
end
puts({ "ruby_platform" => local.to_s, "bundler" => Bundler::VERSION,
       "gems" => out, "path_gems" => path_out, "git_gems" => git_out }.to_json)
"##;
