//! Which Binary Ninja plugins a worker loads, and how that choice reaches it.
//!
//! Out of the box a worker loads Binary Ninja's bundled plugins and nothing else:
//! `InitializationOptions::default()` in the pinned API leaves `user_plugins`
//! off. That is the right default — a plugin can register architectures, view
//! types and analysis workflows, and every one of those changes what the tools
//! answer — but a target whose architecture only exists as a plugin cannot be
//! analyzed at all without one. [Measured] a file whose architecture exists only
//! as a plugin loads as a meaningless x86 `Mapped` view without it, and as a view
//! of its real architecture, with its functions found, with it.
//!
//! Two switches, both operator-level:
//!
//! * `--plugin <PATH>`, repeatable: one native plugin (`.so` / `.dylib`), loaded
//!   by path after the core initializes and before the binary does. See
//!   `src/bn/plugins.rs` for why that order is the whole point.
//! * `--user-plugins`: Binary Ninja's own user plugin directory, the way the GUI
//!   loads it.
//!
//! **Operator-level, never a tool parameter.** Loading a plugin runs its code.
//! On a listener, a `session.open` that took a plugin path would hand every
//! token holder a way to run native code of their choosing, and would also
//! force view reuse to key on the plugin set rather than the path. A set fixed
//! when the process starts has neither problem: every worker this supervisor
//! spawns loads the same plugins, so two opens of one path can still share one
//! view.
//!
//! Global flags, like the policy flags: `serve` has to hand them to every worker
//! it spawns ([`PluginSet::worker_args`]), and `tool` loads a view of its own
//! and has to honour them too.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Arg, ArgAction, ArgMatches};

/// Clap id and long name of `--plugin`.
pub const PLUGIN_ARG: &str = "plugin";
/// Clap id and long name of `--user-plugins`.
pub const USER_PLUGINS_ARG: &str = "user-plugins";

/// The plugins every Binary Ninja session in this process tree loads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PluginSet {
    /// Load Binary Ninja's user plugin directory, as the GUI does.
    pub user_plugins: bool,
    /// Native plugins loaded by path, in the order given.
    pub native: Vec<PathBuf>,
}

impl PluginSet {
    /// The two flags, as `Arg`s for the builder-side root in `main.rs`.
    ///
    /// `global(true)` for the same reason the policy flags are: the `tool` path
    /// resolves a leaf and never parses the root, and `worker` is reached with
    /// these after its own subcommand name.
    pub fn args() -> [Arg; 2] {
        [
            Arg::new(PLUGIN_ARG)
                .long(PLUGIN_ARG)
                .value_name("PATH")
                .action(ArgAction::Append)
                .value_parser(clap::value_parser!(PathBuf))
                .global(true)
                .help(
                    "Load this native Binary Ninja plugin (.so/.dylib) into every worker, \
                     before the binary is loaded. Repeatable; loaded in the order given",
                ),
            Arg::new(USER_PLUGINS_ARG)
                .long(USER_PLUGINS_ARG)
                .action(ArgAction::SetTrue)
                .global(true)
                .help(
                    "Also load the plugins in Binary Ninja's user plugin directory, as the \
                     GUI does. Off by default: a plugin can change what analysis answers",
                ),
        ]
    }

    /// Read both flags off any level of the parsed tree.
    pub fn read(matches: &ArgMatches) -> Self {
        Self {
            user_plugins: matches.get_flag(USER_PLUGINS_ARG),
            native: matches
                .get_many::<PathBuf>(PLUGIN_ARG)
                .map(|paths| paths.cloned().collect())
                .unwrap_or_default(),
        }
    }

    /// Canonicalize every path and drop repeats, refusing one that is not a file.
    ///
    /// Done once, where the flags were typed, rather than in each worker:
    /// `serve` should refuse a misspelled plugin before it binds a port, not on
    /// the first `session.open`, and a worker runs with the supervisor's
    /// working directory rather than the operator's. A repeat is dropped rather
    /// than loaded twice, because loading twice means calling its
    /// `CorePluginInit` twice — registering one architecture under one name two
    /// times.
    pub fn resolve(self) -> anyhow::Result<Self> {
        let mut native: Vec<PathBuf> = Vec::with_capacity(self.native.len());
        for path in self.native {
            let canonical = std::fs::canonicalize(&path)
                .map_err(|e| anyhow::anyhow!("--plugin {}: {e}", path.display()))?;
            if !canonical.is_file() {
                anyhow::bail!(
                    "--plugin {}: not a file (name the plugin's shared library itself, not \
                     the directory it is in)",
                    path.display()
                );
            }
            if !native.contains(&canonical) {
                native.push(canonical);
            }
        }
        Ok(Self {
            user_plugins: self.user_plugins,
            native,
        })
    }

    /// Nothing beyond Binary Ninja's bundled plugins.
    pub fn is_default(&self) -> bool {
        !self.user_plugins && self.native.is_empty()
    }

    /// The same set, spelled as flags for a spawned `worker`.
    ///
    /// The supervisor does not pass its policy flags down (see `run_worker`),
    /// but it has to pass these: a worker is the process that loads them.
    pub fn worker_args(&self) -> Vec<OsString> {
        let mut args = Vec::with_capacity(self.native.len() * 2 + 1);
        for path in &self.native {
            args.push(OsString::from(format!("--{PLUGIN_ARG}")));
            args.push(path.clone().into_os_string());
        }
        if self.user_plugins {
            args.push(OsString::from(format!("--{USER_PLUGINS_ARG}")));
        }
        args
    }

    /// One line for a log or `doctor`.
    pub fn describe(&self) -> String {
        if self.is_default() {
            return "bundled plugins only".to_owned();
        }
        let mut parts: Vec<String> = self
            .native
            .iter()
            .map(|p| format!("native {}", p.display()))
            .collect();
        if self.user_plugins {
            parts.push("the user plugin directory".to_owned());
        }
        format!("bundled plugins plus {}", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> clap::Command {
        clap::Command::new("t")
            .args(PluginSet::args())
            .subcommand(clap::Command::new("worker").arg(Arg::new("input").long("input")))
    }

    fn parse(argv: &[&str]) -> PluginSet {
        let matches = root().get_matches_from(std::iter::once("t").chain(argv.iter().copied()));
        PluginSet::read(&matches)
    }

    #[test]
    fn nothing_typed_means_bundled_plugins_only() {
        let set = parse(&[]);
        assert!(set.is_default());
        assert!(set.worker_args().is_empty());
    }

    /// Both flags are global: typed after a subcommand, they still reach a read
    /// of the root matches — which is where `main` reads them.
    #[test]
    fn the_flags_are_read_wherever_they_were_typed() {
        let set = parse(&[
            "worker",
            "--plugin",
            "/a.so",
            "--plugin",
            "/b.so",
            "--user-plugins",
        ]);
        assert_eq!(
            set.native,
            vec![PathBuf::from("/a.so"), PathBuf::from("/b.so")]
        );
        assert!(set.user_plugins);
    }

    /// What the supervisor hands a worker parses back into the set it started
    /// from, order included — the order is the order plugins initialize in.
    #[test]
    fn worker_args_round_trip_through_the_worker_subcommand() {
        let set = PluginSet {
            user_plugins: true,
            native: vec![PathBuf::from("/x/one.so"), PathBuf::from("/y/two.so")],
        };
        let mut argv: Vec<OsString> =
            vec!["t".into(), "worker".into(), "--input".into(), "f".into()];
        argv.extend(set.worker_args());
        let matches = root().get_matches_from(argv);
        assert_eq!(PluginSet::read(&matches), set);
    }

    #[test]
    fn resolve_canonicalizes_and_drops_repeats() {
        let dir = std::env::temp_dir().join(format!("bn-mcp-plugins-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("libfake.so");
        std::fs::write(&file, b"").unwrap();
        let dotted = dir.join(".").join("libfake.so");

        let resolved = PluginSet {
            user_plugins: false,
            native: vec![file.clone(), dotted],
        }
        .resolve()
        .expect("an existing file resolves");
        assert_eq!(resolved.native, vec![std::fs::canonicalize(&file).unwrap()]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_refuses_a_missing_path_and_a_directory() {
        let missing = PluginSet {
            user_plugins: false,
            native: vec![PathBuf::from("/definitely/not/here.so")],
        }
        .resolve()
        .expect_err("a missing plugin is refused");
        assert!(missing
            .to_string()
            .contains("--plugin /definitely/not/here.so"));

        let directory = PluginSet {
            user_plugins: false,
            native: vec![std::env::temp_dir()],
        }
        .resolve()
        .expect_err("a directory is refused");
        assert!(directory.to_string().contains("not a file"));
    }
}
