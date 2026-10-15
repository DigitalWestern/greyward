//! The hosts a Gemfile's git sources name, read from its text without
//! evaluating it. A Gemfile is Ruby, so this is a scan, not a parse: it
//! finds the places Bundler takes a git remote from (a `git:` option, a
//! `git "..." do` block, a `git_source` definition, and the `github:`,
//! `gist:` and `bitbucket:` shorthands) and reads the host out of the
//! string written there. A Bundler run that writes the lock gets git
//! fetches through the resolution proxy to these hosts and to no other
//! (`Intercept::Git`). A remote the scan cannot read (built by
//! interpolation, or named in a file `eval_gemfile` loads) is not
//! reachable, and Bundler's clone of it is refused, naming the host.

/// The host each shorthand option fetches from, as Bundler's built-in
/// `git_source`s define them.
const SHORTHANDS: &[(&str, &str)] = &[
    ("github", "github.com"),
    ("gist", "gist.github.com"),
    ("bitbucket", "bitbucket.org"),
];

/// The hosts `gemfile`'s git sources fetch from, lowercase, sorted, each
/// once.
pub(super) fn git_hosts(gemfile: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    let lines: Vec<&str> = gemfile.lines().collect();
    for (at, line) in lines.iter().enumerate() {
        let line = line.trim_start();
        if line.starts_with('#') {
            continue;
        }
        // `git "https://host/repo.git" do ... end`
        if let Some(rest) = line
            .strip_prefix("git ")
            .or_else(|| line.strip_prefix("git("))
        {
            hosts.extend(string_after(rest).and_then(host_of));
        }
        for (key, rest) in options(line) {
            match key {
                "git" => hosts.extend(string_after(rest).and_then(host_of)),
                _ => {
                    let host = SHORTHANDS.iter().find(|(name, _)| *name == key);
                    if let (Some((_, host)), Some(_)) = (host, string_after(rest)) {
                        hosts.push(host.to_string());
                    }
                }
            }
        }
        // `git_source(:name) { |repo| "https://host/#{repo}.git" }`, on
        // one line or as a `do ... end` block over the next few.
        if line.starts_with("git_source") {
            for body in lines[at..].iter().take(8) {
                hosts.extend(remotes_in(body).filter_map(host_of));
                if body.contains('}') || body.trim() == "end" {
                    break;
                }
            }
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

/// The option keys `line` names among `git` and the shorthands, each with
/// the text after it: `key: value`, `:key => value` or `"key" => value`.
fn options(line: &str) -> Vec<(&'static str, &str)> {
    let keys = std::iter::once("git").chain(SHORTHANDS.iter().map(|(name, _)| *name));
    let mut found = Vec::new();
    for key in keys {
        let mut from = 0;
        while let Some(offset) = line[from..].find(key) {
            let start = from + offset;
            let end = start + key.len();
            from = end;
            let before = line[..start].chars().next_back();
            if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            let quoted = matches!(before, Some('"' | '\''));
            let mut rest = &line[end..];
            if quoted {
                let Some(stripped) = rest.strip_prefix(['"', '\'']) else {
                    continue;
                };
                rest = stripped;
            }
            // `key: value`, not `key::Const` or a key that runs on.
            if let Some(after) = rest.strip_prefix(':') {
                if after.starts_with(char::is_whitespace) {
                    found.push((key, after));
                }
                continue;
            }
            // `:key => value` or `"key" => value`
            if before == Some(':') || quoted {
                if let Some(after) = rest.trim_start().strip_prefix("=>") {
                    found.push((key, after));
                }
            }
        }
    }
    found
}

/// The string literal `text` opens with, past spaces and an opening
/// parenthesis: its contents up to the closing quote.
fn string_after(text: &str) -> Option<&str> {
    let text = text.trim_start();
    let text = text.strip_prefix('(').unwrap_or(text).trim_start();
    let quote = text.chars().next().filter(|c| matches!(c, '"' | '\''))?;
    let body = &text[1..];
    body.find(quote).map(|end| &body[..end])
}

/// Every remote written in `text`: from each `https://`, `ssh://` or
/// `git@` up to the closing quote or a space.
fn remotes_in(text: &str) -> impl Iterator<Item = &str> {
    let starts: Vec<usize> = ["https://", "ssh://", "git@"]
        .iter()
        .flat_map(|scheme| text.match_indices(scheme).map(|(at, _)| at))
        .collect();
    starts.into_iter().map(move |at| {
        let rest = &text[at..];
        let end = rest
            .find(|c: char| matches!(c, '"' | '\'') || c.is_whitespace())
            .unwrap_or(rest.len());
        &rest[..end]
    })
}

/// The host `remote` fetches from over https, as the git row reaches it:
/// an `https://` URL's host, or an ssh remote's (`ssh://` or
/// `git@host:path`), which the git row rewrites to https. `None` for
/// anything else (`http://` and `git://` are refused, a local path needs
/// no network) and for a host built by interpolation. A port is dropped:
/// the proxy matches a tunnel by its host.
fn host_of(remote: &str) -> Option<String> {
    let (rest, scp) = if let Some(rest) = remote.strip_prefix("https://") {
        (rest, false)
    } else if let Some(rest) = remote.strip_prefix("ssh://") {
        (rest, false)
    } else {
        (remote.strip_prefix("git@")?, true)
    };
    let authority = match scp {
        true => rest.split(':').next()?,
        false => rest.split('/').next()?,
    };
    let host = authority.rsplit('@').next()?;
    let host = match scp {
        true => host,
        false => host.split(':').next()?,
    };
    let host = host.to_ascii_lowercase();
    let plain = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    (plain && !host.is_empty() && !host.starts_with(['.', '-'])).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every place Bundler takes a git remote from is read, in each
    /// spelling; a comment, a `source`, and a remote that is not https
    /// (or an ssh one the git row rewrites to https) add nothing.
    #[test]
    fn git_hosts_are_read_from_every_git_option() {
        let gemfile = r#"source "https://rubygems.org"
# gem "commented", git: "https://commented.example/x.git"
gem "xpath", git: "https://github.com/teamcapybara/xpath.git"
gem "spec", :git => 'https://GitLab.com/a/spec.git', branch: "main"
gem "quoted", "git" => "https://quoted.example/q.git"
gem "short", github: "rails/rails"
gem "gist", gist: "abc123"
gem "bb", :bitbucket => "team/bb"
gem "scp", git: "git@codeberg.org:me/scp.git"
gem "ssh", git: "ssh://git@ssh.example/me/ssh.git"
gem "plain", git: "http://insecure.example/x.git"
gem "daemon", git: "git://daemon.example/x.git"
gem "local", git: "/srv/repos/local"
gem "built", git: "https://#{ENV["HOST"]}/x.git"
gem "port", git: "https://ported.example:8443/x.git"
gem "rails", "~> 8.0", require: "digit: 'not-a-key'"
git "https://block.example/mono.git" do
  gem "member"
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
                "gist.github.com",
                "git.internal.example",
                "github.com",
                "gitlab.com",
                "other.example",
                "ported.example",
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
}
