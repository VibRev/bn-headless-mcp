//! The cross-engine tool-surface contract, as a gate on this engine.
//!
//! Each engine owns its own MCP face, and nothing about that forces three
//! engines to feel alike. `vibrev-kit::contract` is the mechanism that covers
//! the gap, and this module is where this engine submits to it.
//!
//! It is also the thing that makes `vibrev-kit` safe to depend on. kit is a path
//! dependency, so a change over there reaches this repository without going
//! through a version bump — and with kit modules sitting inside the request
//! path, a kit change that breaks this engine has nothing else in the build that
//! would notice before merge. This test is that notice.
//!
//! Nothing here needs a Binary Ninja license or a loaded view. Both catalogs are
//! built from `#[vibrev_tool]` attributes and `session_tools()`, neither of which
//! touches the core, so this gate runs on a machine that cannot run
//! `tests/two_paths.rs`.
//!
//! It lives under `src/` rather than in `tests/` because this is a bin-only
//! crate: with no lib target, an integration test cannot reach the internal
//! modules whose catalogs are the thing being audited.
//!
//! There is no non-test code in this file, and that is deliberate: the contract
//! is not something this engine implements, it is something this engine is
//! checked against.

#[cfg(test)]
mod tests {
    use vibrev_kit::contract::{Audit, SurfaceReport};

    /// Both faces a client can connect to.
    ///
    /// The supervisor's catalog is the worker's with a `view` parameter grafted
    /// on plus the session primitives, so the two are not independent — but they
    /// are not identical either, and the grafting is exactly the kind of step
    /// that can drop a title or strand a `$ref`. Auditing only the worker would
    /// check a surface no client actually speaks to.
    fn both_faces() -> SurfaceReport {
        // `run_repeated` rebuilds each catalog and compares the order: clients
        // render `tools/list` in the order they receive it, so a catalog
        // assembled through a hash map is a snapshot test that fails at random.
        let mut report =
            Audit::new("worker").run_repeated(crate::server::BnMcpServer::vibrev_tool_defs);
        report.merge(Audit::new("supervisor").run_repeated(crate::supervisor::supervisor_tools));
        report
    }

    /// The contract holds, on both faces, with nothing exempted.
    ///
    /// Schemas are normalized in `vibrev-kit::schema`, called from the tool
    /// macro, so this engine publishes the same shapes every other engine does
    /// without writing a normalizer of its own: no leaked `$schema` keys, and no
    /// `Option<T>` parameter spelled as an `anyOf` null branch. Two engines
    /// giving one `Option<u32>` parameter two shapes is exactly what a client
    /// cannot work around.
    ///
    /// Nothing is exempted, so a new kind of drift fails this test rather than
    /// hiding inside a tolerated set of findings.
    #[test]
    fn the_shared_surface_contract_holds() {
        both_faces().assert_clean();
    }

    /// The scan really looked at both catalogs.
    ///
    /// Without this, the test above passes just as well when a catalog builder
    /// starts returning nothing — "no findings" and "nothing checked" are the
    /// same observation from the outside, and a contract test that cannot tell
    /// them apart is the one failure mode it cannot afford. `EmptySurface`
    /// covers the zero case; these bounds cover the "quietly lost half the
    /// catalog" case.
    #[test]
    fn the_scan_covered_both_catalogs() {
        let report = both_faces();
        let checked = report.checked();

        assert!(checked.tools > 90, "expected both faces, got {checked}");
        assert_eq!(
            checked.input_schemas, checked.tools,
            "every tool has an input schema"
        );
        assert_eq!(
            checked.output_schemas, checked.tools,
            "every tool on both faces publishes an outputSchema"
        );
        assert!(checked.refs > 0, "expected schemas with $ref to exist");
    }

    /// The four hand-built session tools are normalized too.
    ///
    /// `assert_clean` above would catch a regression here, but not say what it
    /// was. These four are the only tools in this engine no macro expands —
    /// `Tool::with_output_schema` hands schemars' product through untouched — so
    /// they are the one place where the normalization has to be asked for by
    /// name, and the one place where forgetting is possible.
    #[test]
    fn the_session_primitives_go_through_the_same_normalizer() {
        for tool in crate::supervisor::supervisor_tools()
            .into_iter()
            .filter(|tool| tool.name.starts_with("session.") || tool.name == "health.ping")
        {
            let output = tool.output_schema.as_ref().expect("an output schema");
            assert!(
                !serde_json::to_string(output)
                    .expect("schema is JSON")
                    .contains("\"$schema\""),
                "{} still advertises its dialect",
                tool.name
            );
        }
    }
}
