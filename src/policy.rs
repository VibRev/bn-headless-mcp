//! What this engine tells `vibrev-kit::policy` about itself.
//!
//! The mechanism — how `--toolsets`, `--tools`, `--exclude-tools`,
//! `--read-only` and `--unsafe` compose, in what order, and what happens when
//! they cancel out — lives in the kit, shared with `ida-headless-mcp`. What is
//! left here is the part that is genuinely about Binary Ninja: two lists, and
//! the observation that this engine's tool names are already a taxonomy.
//!
//! Nineteen of the forty-seven tools write: the whole `patch` group, four
//! `annotation` verbs, `type.apply`, `type.set_function_prototype`,
//! `function.set_variable`, three `database` verbs, and both `script` verbs.
//! `--read-only` is what starts the server without them.

use vibrev_kit::policy::{PolicyArgs, PolicyError, Taxonomy, ToolPolicy};
use vibrev_kit::Advertised;

/// The session primitives, which survive every narrowing but an explicit
/// exclusion.
///
/// The supervisor injects a **required** `view` parameter into every analysis
/// tool, and `session.open` is the only thing that hands a view out. So dropping
/// it leaves a server whose every remaining tool answers "needs `view`" with no
/// way to obtain one — and it gets dropped by two unrelated routes:
///
/// * `--read-only`, because `session.open` is honestly annotated
///   `read_only = false`: it takes a license seat and starts a process.
/// * `--toolsets patch`, because opening a view is not patching.
///
/// Without this list, `--toolsets patch` advertises eight patch tools and not
/// one of them can be called.
///
/// `session.close` matters for a smaller but real reason: Binary Ninja cannot be
/// re-initialized in a process, so closing the view *is* how memory comes back.
/// A session that could open views and never release them leaks a worker per
/// binary. `session.list` and `health.ping` are here because they are the
/// supervisor's own bookkeeping rather than anything in this engine's domain —
/// no category a user picks is a statement about them.
const ESSENTIAL: &[&str] = &[
    "session.open",
    "session.close",
    "session.list",
    "health.ping",
];

/// Build the policy for one face from the catalog that face advertises.
///
/// The catalog is a parameter rather than a constant because the two faces are
/// not the same list: the supervisor advertises the four `session.*` primitives
/// on top of the worker's tools. Building each policy against the catalog it
/// governs is what stops `--tools=session.open` from being accepted on a face
/// that has no such tool.
///
/// The taxonomy comes free. `patch.nop` and `patch.bytes` already say they are
/// the `patch` group; writing that down a second time as a `match` would be two
/// things to keep in step.
pub fn build<T: Advertised>(catalog: &[T], args: &PolicyArgs) -> Result<ToolPolicy, PolicyError> {
    args.apply(
        ToolPolicy::builder(catalog)
            .taxonomy(Taxonomy::by_dot_prefix(catalog))
            .essential(ESSENTIAL),
    )
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worker() -> Vec<vibrev_kit::ToolDef> {
        crate::server::BnMcpServer::vibrev_tool_defs()
    }

    fn args() -> PolicyArgs {
        // What a user who passed no flags gets: everything.
        PolicyArgs::default()
    }

    /// The server starts read-only, on the face a client actually connects to.
    #[test]
    fn the_supervisor_can_be_started_read_only() {
        let catalog = crate::supervisor::supervisor_tools();
        let policy = build(
            &catalog,
            &PolicyArgs {
                read_only: true,
                ..args()
            },
        )
        .expect("policy");

        for writer in [
            "patch.nop",
            "patch.bytes",
            "patch.assemble",
            "annotation.rename_function",
            "annotation.set_comment",
            "type.apply",
            "type.set_function_prototype",
            "function.set_variable",
            "database.create_bndb",
            "database.save",
            "database.export_binary",
            "script.python",
            "script.reset",
        ] {
            assert!(!policy.allows(writer), "{writer} survived --read-only");
        }

        for reader in ["binary.functions", "il.pseudo_c", "xref.code_refs_to"] {
            assert!(policy.allows(reader), "{reader}");
        }
    }

    /// …and it is still usable, which is the half that is easy to get wrong.
    #[test]
    fn a_read_only_server_can_still_open_and_close_a_view() {
        let catalog = crate::supervisor::supervisor_tools();
        let policy = build(
            &catalog,
            &PolicyArgs {
                read_only: true,
                ..args()
            },
        )
        .expect("policy");

        // Both are annotated `read_only = false` and both survive: every
        // analysis tool requires a `view`, and `session.open` is the only thing
        // that hands one out.
        assert!(policy.allows("session.open"));
        assert!(policy.allows("session.close"));
        assert!(policy.allows("session.list"));
        assert!(policy.allows("health.ping"));
    }

    /// The tool that runs arbitrary Python is offered by default, like every
    /// other tool this engine ships.
    ///
    /// A capability withheld by default is one the operator finds by asking why
    /// it is missing, and hiding it behind a flag would break everyone already
    /// calling it. An operator who wants it gone says so with
    /// `--exclude-tools`; a listener says so in its banner.
    #[test]
    fn arbitrary_code_is_offered_like_anything_else() {
        let catalog = worker();
        let policy = build(&catalog, &args()).expect("policy");

        assert!(policy.allows("script.python"));
        assert!(
            policy
                .advertise(catalog.clone())
                .iter()
                .any(|def| def.name() == "script.python"),
            "script.python belongs in tools/list"
        );

        // …and an operator who wants it gone says so.
        let without = build(
            &catalog,
            &PolicyArgs {
                exclude_tools: vec!["script.python".to_string()],
                ..args()
            },
        )
        .expect("policy");
        assert!(!without.allows("script.python"));
    }

    /// No flags must not narrow anything. A policy that quietly dropped a tool
    /// would be a silent breaking change for every existing user.
    #[test]
    fn the_default_hides_nothing_at_all() {
        let catalog = worker();
        let policy = build(&catalog, &args()).expect("policy");
        assert_eq!(policy.advertise(catalog.clone()).len(), catalog.len());
        assert!(!policy.is_active());
    }

    /// The dot prefixes really do partition this engine's surface — a tool with
    /// no group would be selectable only by name, which is worth knowing about.
    #[test]
    fn every_tool_belongs_to_a_group() {
        let ungrouped: Vec<String> = worker()
            .iter()
            .map(|def| def.name().to_string())
            .filter(|name| !name.contains('.'))
            .collect();
        assert!(ungrouped.is_empty(), "ungrouped tools: {ungrouped:?}");
    }

    #[test]
    fn a_group_can_be_selected_and_narrows_to_it() {
        let catalog = worker();
        let policy = build(
            &catalog,
            &PolicyArgs {
                toolsets: vec!["patch".to_string()],
                ..args()
            },
        )
        .expect("policy");

        let advertised: Vec<String> = policy
            .advertise(catalog)
            .iter()
            .map(|def| def.name().to_string())
            .collect();
        assert_eq!(advertised.len(), 8, "the patch group: {advertised:?}");
        assert!(advertised.iter().all(|name| name.starts_with("patch.")));
    }

    /// The worker face has no `session.*`, so naming one there is a mistake
    /// worth reporting rather than an empty result.
    #[test]
    fn a_tool_from_the_other_face_is_rejected_not_ignored() {
        assert_eq!(
            build(
                &worker(),
                &PolicyArgs {
                    tools: vec!["session.open".to_string()],
                    ..args()
                },
            )
            .unwrap_err(),
            PolicyError::UnknownTool("session.open".to_string())
        );
    }
}
