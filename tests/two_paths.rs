//! The two-path claim, checked against a real Binary Ninja: what `tools/call`
//! puts in `content[0].text` is byte for byte what `bn-headless-mcp tool …`
//! prints.
//!
//! It is not a tautology. These are the three places the bytes can diverge:
//!
//! 1. **A second renderer.** The derived CLI has to hand its payload to the
//!    same `IntoCallToolResult` dispatch the MCP path uses. A CLI that renders
//!    the payload itself makes the two paths two producers that happen to
//!    agree.
//! 2. **A supervisor that rebuilds `content`.** A supervisor that takes the
//!    worker's `structuredContent` and formats fresh text leaves the surface
//!    clients actually connect to *not* the surface the guarantee was measured
//!    on. This supervisor must forward results verbatim, and this suite checks
//!    it as well as the worker behind it.
//! 3. **`Json<T>`.** rmcp's own wrapper overwrites `content` with the compact
//!    serialization, which would turn every line of pseudocode into `\n` inside
//!    one escaped string.
//!
//! What it is *not* about is whether two Binary Ninja processes analyzing one
//! file reach the same conclusions. They need not, and asserting that they do
//! would be asserting something false. The two byte-comparison tests therefore
//! load a pre-built `.bndb` — see [`shared_analysis`] — so that there is one
//! analysis and any difference is a difference in rendering.
//!
//! These need a working Binary Ninja and a license. Without one they skip with a
//! printed reason rather than fail — a red suite that only means "not installed
//! here" trains people to ignore it.

use std::process::Stdio;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, CancelTaskParams, ClientCapabilities,
    ClientInfo, DetailedTask, GetTaskParams, Implementation, ProtocolVersion, TaskPayload,
    TaskStatus,
};
use rmcp::service::{Peer, RoleClient};
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::ServiceExt;
use serde_json::{json, Map, Value};
use vibrev_kit::output::{Limits, META_KEY};

const EXE: &str = env!("CARGO_BIN_EXE_bn-headless-mcp");

/// Small, present on every Linux box, and analyzed in a couple of seconds.
const TARGET: &str = "/bin/cat";

/// The read-only tools, with arguments, in an order no earlier call can change.
fn read_only_calls() -> Vec<(&'static str, Map<String, Value>)> {
    vec![
        ("binary.segments", Map::new()),
        ("binary.sections", Map::new()),
        ("binary.functions", object(json!({"limit": 5, "offset": 2}))),
        ("binary.strings", object(json!({"limit": 5}))),
        ("binary.survey", Map::new()),
        ("il.pseudo_c", object(json!({"target": "main"}))),
        ("disasm.function", object(json!({"target": "main"}))),
        (
            "xref.code_refs_to",
            object(json!({"target": "main", "limit": 10})),
        ),
        (
            "xref.code_refs_from",
            object(json!({"target": "main", "limit": 10})),
        ),
        (
            "function.callers",
            object(json!({"target": "main", "limit": 10})),
        ),
        (
            "function.callees",
            object(json!({"target": "main", "limit": 10})),
        ),
        (
            "xref.data_refs_to",
            object(json!({"target": "main", "limit": 10})),
        ),
        (
            "xref.data_refs_from",
            object(json!({"target": "main", "limit": 10})),
        ),
        ("binary.symbols", object(json!({"limit": 5}))),
        ("binary.imports", object(json!({"limit": 5}))),
        ("annotation.get_comment", object(json!({"target": "main"}))),
        (
            "function.basic_blocks",
            object(json!({"target": "main", "limit": 10})),
        ),
        ("function.analyze", object(json!({"target": "main"}))),
        (
            "analyze.trace_data_flow",
            object(json!({"target": "main", "max_depth": 2})),
        ),
        ("binary.data_vars", object(json!({"limit": 5}))),
        (
            "binary.search",
            object(json!({"query": "4889e5", "limit": 5})),
        ),
        (
            "binary.search",
            object(json!({"query": "push", "kind": "text", "limit": 5})),
        ),
        (
            "binary.symbols",
            object(json!({"limit": 5, "kind": "function"})),
        ),
        (
            "function.variables",
            object(json!({"target": "main", "limit": 5})),
        ),
        (
            "annotation.get_function_comment",
            object(json!({"target": "main"})),
        ),
    ]
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

/// Serializes the tests, because fifteen of them each start their own headless
/// Binary Ninja and one box will not hold that many analyses at once. That is
/// the whole of the reason, and nothing this guard protects is a correctness
/// claim.
///
/// It does not, in particular, make the two-path comparisons agree. Two
/// independent Binary Ninja processes reading one file are not obliged to reach
/// the same analysis, and load has nothing to do with it: [Measured] serially,
/// on an idle box, `function.callees` for `main` comes back with 17 callees on
/// one side and 18 on the other — differing by `sub_402069` (0x402069, 125
/// bytes, 5 basic blocks), agreeing on every other field, key order, indent and
/// byte, and both reporting `analysis_coverage.complete: true`.
/// `update_analysis_and_wait` makes *one* view's answer final, which is a
/// different promise, and `analysis_coverage` describes one view rather than
/// two. [`shared_analysis`] is what removes that confounder: both paths load
/// one pre-built `.bndb`, so there is one analysis to render and the comparison
/// is about rendering again.
///
/// Async-aware on purpose: the guard is held across every `await` in a test, and
/// a `std` mutex there is what `clippy::await_holding_lock` is for. Tokio's also
/// does not poison, so one failing test does not cascade into five.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn exclusive() -> tokio::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().await
}

/// One analysis of [`TARGET`], saved to a `.bndb`, that both sides of a
/// byte-comparison load instead of each computing their own.
///
/// This is the confounder removal the comment above describes.
/// `worker_and_cli_produce_the_same_bytes` runs one worker against
/// twenty-eight freshly spawned CLI processes; when each of those analyzed
/// `/bin/cat` from scratch, a byte difference had two possible causes — a
/// second renderer, which is what the test exists to catch, and two analyses
/// that disagreed, which is not something the test should be asserting is
/// impossible, because it is not. Loading a database removes the second cause:
/// every process renders the analysis that was computed once, here.
///
/// [Measured] the database is a fixed point, and that is the property the fix
/// rests on rather than an assumption. `Engine::open` passes
/// `update_analysis_and_wait = true` for a `.bndb` as well, so a load is not a
/// pure restore — on `/bin/cat` that pass finds a call from `main` to
/// `sub_402069` that a load of the raw ELF does not, which is 18 callees
/// against 17 — the same split [`ONE_AT_A_TIME`] describes, reproduced here on
/// demand rather than intermittently (50 raw loads, sequential and six at a
/// time, all answered 17; five independently built `.bndb`s all answered 18;
/// and saving inside a raw view changes nothing, so it is the load that
/// converges, not the save). What matters is that it finds it *every* time: 110
/// loads of a fixture like this one, sequential and six at a time, produced a
/// single distinct answer. The raw file diverges; the database does not.
///
/// Built once for the whole test binary. The two tests that want it are
/// serialized by [`ONE_AT_A_TIME`] anyway, and the analysis costs about three
/// seconds.
///
/// The path is canonicalized because `session.open` canonicalizes before it
/// hands `--input` to a worker (`src/supervisor/mod.rs`), and `binary.survey`
/// echoes `input_path` — the same reason [`requirements`] canonicalizes the
/// target. Two spellings of one file would read as a mismatch.
static SHARED_ANALYSIS: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();

async fn shared_analysis(target: &str) -> &'static str {
    SHARED_ANALYSIS
        .get_or_init(|| async {
            // Not `/tmp`, for the reason `patches_survive_a_bndb_and_an_exported_binary`
            // gives below: this workspace runs on a tmpfs that is routinely near
            // full, and this file is ~650 KiB. The name has to stay clear of that
            // test's `patched.bndb`, which holds a *patched* view on purpose.
            let scratch = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
            std::fs::create_dir_all(scratch).expect("scratch dir");
            let bndb = scratch.join("shared_analysis.bndb");
            // Rebuilt every run rather than cached across runs: `CARGO_TARGET_TMPDIR`
            // outlives the run, and a fixture left over from before a system
            // update would quietly test yesterday's `/bin/cat`.
            let _ = std::fs::remove_file(&bndb);
            let path = bndb.to_string_lossy().into_owned();
            cli(&["tool", "database", "create_bndb", &path], target)
                .expect("build the shared .bndb the two-path comparisons load");
            std::fs::canonicalize(&bndb)
                .expect("the fixture is there once create_bndb reports it created")
                .to_string_lossy()
                .into_owned()
        })
        .await
}

/// Skip rather than fail when Binary Ninja cannot run here.
///
/// Returns the canonical target path, so every path under test is given the
/// same string — `binary.survey` echoes `input_path`, and `/bin/cat` versus
/// `/usr/bin/cat` would look like a mismatch that is really a symlink.
fn requirements() -> Option<String> {
    if std::env::var_os("BN_LICENSE").is_none() && !dirs_license_exists() {
        eprintln!(
            "SKIP: no Binary Ninja license found. Set BN_LICENSE, or put license.dat in the \
             Binary Ninja user directory. Headless needs Commercial or Ultimate."
        );
        return None;
    }
    match std::fs::canonicalize(TARGET) {
        Ok(path) => Some(path.to_string_lossy().into_owned()),
        Err(e) => {
            eprintln!("SKIP: {TARGET} is not present here ({e})");
            None
        }
    }
}

fn dirs_license_exists() -> bool {
    let Some(home) = std::env::var_os("HOME") else {
        return false;
    };
    std::path::Path::new(&home)
        .join(".binaryninja/license.dat")
        .exists()
}

/// Run one tool through the CLI and return stdout with the one trailing newline
/// `println!` adds removed.
fn cli(args: &[&str], input: &str) -> Result<String, String> {
    let output = std::process::Command::new(EXE)
        .args(args)
        .arg("--input")
        .arg(input)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("could not run the CLI: {e}"))?;
    if !output.status.success() {
        return Err(format!("{} exited with {}", args.join(" "), output.status));
    }
    let mut text = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
    if text.ends_with('\n') {
        text.pop();
    }
    Ok(text)
}

/// `content[0].text` out of a tool response, refusing anything that is not
/// exactly one text block — a second block would make "the bytes" ambiguous.
fn only_text(result: CallToolResult, tool: &str) -> String {
    assert_eq!(
        result.content.len(),
        1,
        "{tool} returned {} content blocks; the CLI can only print one",
        result.content.len()
    );
    result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .unwrap_or_else(|| panic!("{tool} returned no text content"))
}

fn spawn(args: &[&str]) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(EXE);
    cmd.args(args);
    cmd.kill_on_drop(true);
    cmd
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_and_cli_produce_the_same_bytes() {
    let _serial = exclusive().await;
    let Some(target) = requirements() else { return };
    // One worker against twenty-eight fresh CLI processes, all reading one
    // saved analysis rather than each computing its own. See [`shared_analysis`].
    let input = shared_analysis(&target).await;

    let transport =
        TokioChildProcess::new(spawn(&["worker", "--input", input])).expect("spawn worker");
    let worker = ().serve(transport).await.expect("worker initialize");

    for (tool, args) in read_only_calls() {
        let response = worker
            .peer()
            .call_tool(CallToolRequestParams::new(tool).with_arguments(args.clone()))
            .await
            .unwrap_or_else(|e| panic!("{tool} over MCP: {e}"));
        let mcp_text = only_text(response, tool);

        let argv = cli_argv(tool, &args);
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let cli_text = cli(&refs, input).unwrap_or_else(|e| panic!("{tool} over CLI: {e}"));

        assert_eq!(
            mcp_text, cli_text,
            "{tool}: MCP content[0].text and CLI stdout differ"
        );
        assert!(!mcp_text.is_empty(), "{tool} produced nothing at all");
    }

    // `memory.read` / `disasm.range` need a mapped address. PIE `/bin/cat` is
    // not at `0x400000`; the first function's start is.
    let listed = worker
        .peer()
        .call_tool(
            CallToolRequestParams::new("binary.functions")
                .with_arguments(object(json!({"limit": 1}))),
        )
        .await
        .expect("binary.functions for a mapped address");
    let start = listed
        .structured_content
        .as_ref()
        .and_then(|v| v.get("functions"))
        .and_then(|v| v.as_array())
        .and_then(|v| v.first())
        .and_then(|v| v.get("start"))
        .and_then(Value::as_str)
        .expect("binary.functions returns a start")
        .to_owned();
    for (tool, args) in [
        (
            "memory.read",
            object(json!({"address": start, "length": 16})),
        ),
        (
            "disasm.range",
            object(json!({"start": start, "length": 32, "limit": 8})),
        ),
        (
            "type.parse_declarations",
            object(json!({"source": "typedef int i32;"})),
        ),
    ] {
        let response = worker
            .peer()
            .call_tool(CallToolRequestParams::new(tool).with_arguments(args.clone()))
            .await
            .unwrap_or_else(|e| panic!("{tool} over MCP: {e}"));
        let mcp_text = only_text(response, tool);
        let argv = cli_argv(tool, &args);
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let cli_text = cli(&refs, input).unwrap_or_else(|e| panic!("{tool} over CLI: {e}"));
        assert_eq!(
            mcp_text, cli_text,
            "{tool}: MCP content[0].text and CLI stdout differ"
        );
        assert!(!mcp_text.is_empty(), "{tool} produced nothing at all");
    }

    // The write path last, so nothing above sees a renamed function. Both sides
    // load the saved analysis and neither writes it back, so each rename is
    // against the same `sub_402040` and `old_name` is the same on both.
    let args = object(json!({"target": "0x402040", "new_name": "renamed_by_test"}));
    let response = worker
        .peer()
        .call_tool(
            CallToolRequestParams::new("annotation.rename_function").with_arguments(args.clone()),
        )
        .await
        .expect("rename over MCP");
    let mcp_text = only_text(response, "annotation.rename_function");
    let cli_text = cli(
        &[
            "tool",
            "annotation",
            "rename_function",
            "0x402040",
            "renamed_by_test",
        ],
        input,
    )
    .expect("rename over CLI");
    assert_eq!(mcp_text, cli_text, "annotation.rename_function differs");

    worker.cancel().await.ok();
}

/// The argv that reaches the same tool through the derived CLI.
fn cli_argv(tool: &str, args: &Map<String, Value>) -> Vec<String> {
    let mut argv = vec!["tool".to_owned()];
    match tool.split_once('.') {
        Some((group, verb)) => {
            argv.push(group.to_owned());
            argv.push(verb.to_owned());
        }
        None => argv.push(tool.to_owned()),
    }
    // Positionals used by this engine, in the order clap expects them.
    // Flag-only keys stay in the loop below.
    const POSITIONALS: &[&str] = &[
        "target", "address", "start", "source", "query", "name", "path", "new_name", "comment",
    ];
    for key in POSITIONALS {
        if let Some(Value::String(value)) = args.get(*key) {
            argv.push(value.clone());
        }
    }
    for (name, value) in args {
        if POSITIONALS.contains(&name.as_str()) {
            continue;
        }
        argv.push(format!("--{}", name.replace('_', "-")));
        argv.push(match value {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        });
    }
    argv
}

/// Clients connect to the supervisor, so the guarantee has to hold *there*, not
/// only on the worker behind it.
#[tokio::test(flavor = "multi_thread")]
async fn the_supervisor_forwards_worker_bytes_verbatim() {
    let _serial = exclusive().await;
    let Some(target) = requirements() else { return };
    // Same saved analysis on both sides, for the same reason
    // `worker_and_cli_produce_the_same_bytes` uses it: the worker behind the
    // supervisor and every CLI process below must render one analysis, not
    // twenty-six of their own. `session.open` canonicalizes the path before it
    // reaches the worker, which is why [`shared_analysis`] hands back a
    // canonical one — `binary.survey` echoes `input_path` verbatim.
    let input = shared_analysis(&target).await;

    let transport =
        TokioChildProcess::new(spawn(&["serve", "--mode", "stdio"])).expect("spawn supervisor");
    let supervisor = ().serve(transport).await.expect("supervisor initialize");

    // health.ping must work before anything is open — that is the point.
    let ping = supervisor
        .peer()
        .call_tool(CallToolRequestParams::new("health.ping"))
        .await
        .expect("health.ping");
    assert_ne!(ping.is_error, Some(true), "health.ping failed");
    let ping_body = ping
        .structured_content
        .expect("health.ping publishes structuredContent");
    assert_eq!(ping_body.get("status"), Some(&json!("ok")));

    let opened = supervisor
        .peer()
        .call_tool(
            CallToolRequestParams::new("session.open")
                .with_arguments(object(json!({"path": input}))),
        )
        .await
        .expect("session.open");
    let structured = opened
        .structured_content
        .expect("session.open publishes structuredContent");
    let view = structured
        .get("view")
        .and_then(Value::as_str)
        .expect("session.open returns a view handle")
        .to_owned();

    for (tool, mut args) in read_only_calls() {
        args.insert("view".to_owned(), json!(view));
        let response = supervisor
            .peer()
            .call_tool(CallToolRequestParams::new(tool).with_arguments(args.clone()))
            .await
            .unwrap_or_else(|e| panic!("{tool} through the supervisor: {e}"));
        let routed = only_text(response, tool);

        args.remove("view");
        let argv = cli_argv(tool, &args);
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let direct = cli(&refs, input).unwrap_or_else(|e| panic!("{tool} over CLI: {e}"));

        assert_eq!(
            routed, direct,
            "{tool}: the supervisor re-rendered instead of forwarding"
        );
    }

    // Closing has to actually kill the worker; that is the only way Binary
    // Ninja's memory comes back (Vector35/binaryninja-api#6660).
    let closed = supervisor
        .peer()
        .call_tool(
            CallToolRequestParams::new("session.close")
                .with_arguments(object(json!({"view": view}))),
        )
        .await
        .expect("session.close");
    assert_ne!(
        closed.is_error,
        Some(true),
        "session.close reported failure"
    );

    supervisor.cancel().await.ok();
}

/// `analysis_coverage` on live data, not on the schema: an aggregate answered by
/// a converged view has to say so, and say so in the field a client is told to
/// read.
#[tokio::test(flavor = "multi_thread")]
async fn aggregates_report_their_analysis_coverage() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    let transport =
        TokioChildProcess::new(spawn(&["worker", "--input", &input])).expect("spawn worker");
    let worker = ().serve(transport).await.expect("worker initialize");

    for tool in [
        "binary.segments",
        "binary.sections",
        "binary.functions",
        "binary.strings",
        "binary.symbols",
        "binary.imports",
        "binary.survey",
        "binary.data_vars",
    ] {
        let response = worker
            .peer()
            .call_tool(CallToolRequestParams::new(tool))
            .await
            .unwrap_or_else(|e| panic!("{tool}: {e}"));
        let structured = response
            .structured_content
            .unwrap_or_else(|| panic!("{tool} publishes no structuredContent"));
        let coverage = structured.get("analysis_coverage").unwrap_or_else(|| {
            panic!("{tool} aggregates over the whole view and must say how complete it was")
        });
        assert_eq!(
            coverage.get("complete"),
            Some(&json!(true)),
            "{tool}: the worker answered before analysis settled"
        );
        assert_eq!(coverage.get("engine_state"), Some(&json!("IdleState")));
    }

    worker.cancel().await.ok();
}

/// A tool that fails has to fail the same way on both fronts: `isError: true`
/// over MCP, a non-zero exit with the message on stderr from the CLI.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_tool_reports_failure_on_both_front_ends() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    let transport =
        TokioChildProcess::new(spawn(&["worker", "--input", &input])).expect("spawn worker");
    let worker = ().serve(transport).await.expect("worker initialize");

    let response = worker
        .peer()
        .call_tool(
            CallToolRequestParams::new("il.pseudo_c")
                .with_arguments(object(json!({"target": "no_such_function"}))),
        )
        .await
        .expect("a tool-level failure is still a successful JSON-RPC response");
    assert_eq!(
        response.is_error,
        Some(true),
        "a missing function must be isError:true, not an empty success"
    );

    let output = std::process::Command::new(EXE)
        .args(["tool", "il", "pseudo_c", "no_such_function", "--input"])
        .arg(&input)
        .output()
        .expect("run the CLI");
    assert_eq!(output.status.code(), Some(1), "CLI must exit non-zero");
    assert!(
        output.stdout.is_empty(),
        "a failure must not print to stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no_such_function"),
        "the CLI must name what it could not find"
    );

    worker.cancel().await.ok();
}

/// The two ways a bounded answer can be wrong about its own bounds.
///
/// One worker, because they are one subject: a tool that limits what it returns
/// has to say *whether the limit is why it stopped*, and has to refuse a bound
/// it cannot honour rather than answer as if it had.
///
/// `truncated` is the interesting half. `bn::disasm::render_range` renders one
/// line past the page and then drops it, which is what makes `truncated` an
/// observation instead of a guess. The cheap version — `lines.len() >= limit` —
/// agrees with it on every input except one: a range that ends exactly on the
/// last line the limit allowed. So the middle of the three calls below is the
/// point of the whole exercise, and it is the one that goes red if that trick is
/// ever removed as an optimisation.
///
/// [Measured] that was checked rather than assumed. Dropping the `+ 1` and
/// answering `lines.len() >= limit` makes the 128-byte range below report
/// `truncated: true` under a limit of 43 — with all 43 of its lines in hand and
/// nothing withheld.
#[tokio::test(flavor = "multi_thread")]
async fn a_limit_reports_whether_it_cut_the_answer_and_a_negative_offset_is_refused() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    let transport =
        TokioChildProcess::new(spawn(&["worker", "--input", &input])).expect("spawn worker");
    let worker = ().serve(transport).await.expect("worker initialize");

    let raw = |tool: &'static str, args: Map<String, Value>| {
        let peer = worker.peer().clone();
        async move {
            peer.call_tool(CallToolRequestParams::new(tool).with_arguments(args))
                .await
                .unwrap_or_else(|e| panic!("{tool}: {e}"))
        }
    };
    let structured = |tool: &'static str, args: Map<String, Value>| {
        let peer = worker.peer().clone();
        async move {
            let response = peer
                .call_tool(CallToolRequestParams::new(tool).with_arguments(args))
                .await
                .unwrap_or_else(|e| panic!("{tool}: {e}"));
            assert_ne!(response.is_error, Some(true), "{tool} failed: {response:?}");
            response
                .structured_content
                .unwrap_or_else(|| panic!("{tool} publishes no structuredContent"))
        }
    };

    // The range has to be found rather than written down: `/bin/cat` is PIE, so
    // `0x400000` is nothing. Same reason `worker_and_cli_produce_the_same_bytes`
    // asks first.
    let start = structured("binary.functions", object(json!({"limit": 1})))
        .await
        .get("functions")
        .and_then(Value::as_array)
        .and_then(|functions| functions.first())
        .and_then(|function| function.get("start"))
        .and_then(Value::as_str)
        .expect("binary.functions returns a start")
        .to_owned();

    // 128 bytes from the first function: long enough that the listing is many
    // lines, short enough that a limit of 200 cannot bite. [Measured] on
    // `/bin/cat` that is 43 lines from `0x402000` — `_init`, the two section
    // boundaries, the inter-section padding rendered as bytes, and the head of
    // `sub_402040`.
    let listing = |limit: i64| {
        structured(
            "disasm.range",
            object(json!({"start": start.clone(), "length": 128, "limit": limit})),
        )
    };

    // 1. A limit far above what the range holds, to find N by observation. Note
    //    that this call is already an assertion: if 200 were not generous, every
    //    number below would be measuring the limit rather than the range.
    let whole = listing(200).await;
    assert_eq!(
        whole.get("truncated"),
        Some(&json!(false)),
        "200 lines is more than 128 bytes of code can produce: {whole:?}"
    );
    let text = whole
        .get("listing")
        .and_then(Value::as_str)
        .expect("disasm.range returns a listing");
    // `split` rather than `lines`: the field is a `Vec::join("\n")`, so the
    // number of pieces *is* the number of lines rendered, and `lines()` would
    // quietly lose a trailing empty one.
    let n = text.split('\n').count() as i64;
    assert!(
        (2..200).contains(&n),
        "the range has to hold more than one line and fewer than 200; it rendered {n}"
    );

    // 2. A limit of exactly N. The range ends on the last line the limit allowed
    //    through, which is the single input where "did the limit stop me?" and
    //    "did I collect `limit` lines?" give different answers. Nothing was
    //    withheld here, and an implementation that reported `lines.len() >=
    //    limit` would say otherwise.
    let exact = listing(n).await;
    assert_eq!(
        exact.get("truncated"),
        Some(&json!(false)),
        "a listing that stops because the range ended is not truncated, even when it \
         is exactly `limit` lines long: {exact:?}"
    );
    assert_eq!(
        exact.get("listing"),
        whole.get("listing"),
        "a limit of {n} returned something other than the {n} lines the range holds"
    );

    // 3. One less. Now a line really was held back, and the same field has to
    //    say so — otherwise a caller reads a partial listing as a whole one.
    let cut = listing(n - 1).await;
    assert_eq!(
        cut.get("truncated"),
        Some(&json!(true)),
        "a limit of {} held back the last of {n} lines and did not say so: {cut:?}",
        n - 1
    );
    assert_eq!(
        cut.get("listing")
            .and_then(Value::as_str)
            .map(|listing| listing.split('\n').count() as i64),
        Some(n - 1),
        "`truncated` was right but the page is not the size that was asked for"
    );

    // The other half: a bound that cannot exist at all.
    //
    // `offset` travels as `i64` because a published input schema may not carry
    // `uint32`, which leaves the declared `minimum: 0` as advice a client is free
    // to ignore. `-5i64 as usize` is 18446744073709551611 — an offset past the
    // end of every list — so a cast would answer with an empty page, which reads
    // exactly like "you have reached the end".
    //
    // The control goes first. Without it, "the call failed" is not evidence about
    // `offset`: a worker that had died would fail this call too.
    let ordinary = structured("binary.functions", object(json!({"offset": 0, "limit": 5}))).await;
    assert_eq!(
        ordinary
            .get("functions")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(5),
        "the control call did not come back with a page: {ordinary:?}"
    );

    let refused = raw(
        "binary.functions",
        object(json!({"offset": -5, "limit": 5})),
    )
    .await;
    assert_eq!(
        refused.is_error,
        Some(true),
        "a negative offset came back as a page rather than as a refusal: {refused:?}"
    );
    assert!(
        refused.structured_content.is_none(),
        "the refusal carried a page anyway: {refused:?}"
    );
    // [Measured] `invalid parameters: offset (-5) is out of range for usize`. The
    // two substrings rather than the whole sentence: what has to hold is that a
    // model reading this can tell it wrote the argument wrong, and which one.
    let message = only_text(refused, "binary.functions");
    assert!(
        message.contains("invalid parameters") && message.contains("offset"),
        "the refusal has to read as a parameter problem and name the parameter: {message}"
    );

    // The CLI refuses it too — and it is worth being exact about why, because
    // this one never reaches `page()`. The derived CLI coerces each argument
    // against the schema it was built from, so `minimum: 0` stops `-5` during
    // argument parsing, one layer above where the MCP path refuses it. Both
    // fronts say no; only the call above exercises the `i64` conversion.
    //
    // `--offset=-5` rather than `--offset -5`: clap reads a bare `-5` as a flag.
    let output = std::process::Command::new(EXE)
        .args([
            "tool",
            "binary",
            "functions",
            "--offset=-5",
            "--limit",
            "5",
            "--input",
        ])
        .arg(&input)
        .output()
        .expect("run the CLI");
    assert!(!output.status.success(), "the CLI served a negative offset");
    assert!(
        output.stdout.is_empty(),
        "a refusal must not print a page: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("offset"),
        "the CLI must name the parameter it refused: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    worker.cancel().await.ok();
}

/// The output net, end to end: an answer over the threshold arrives as a
/// preview, and the whole of it is where the answer says it is.
///
/// Straight at a worker rather than through `serve`, because `Capped` wraps the
/// worker and nothing else (`src/main.rs`): that is where an oversized answer is
/// produced, and the supervisor's job is to forward what it is handed verbatim.
/// A test that went through the supervisor would be measuring nothing.
///
/// `script.python` is the overflow rather than an analysis tool that is hopefully
/// large enough. Its own stdout cap is 256 KiB, five times the 50,000-character
/// threshold, so `print('A' * 100000)` overflows by construction and does not
/// depend on anything in particular being inside `/bin/cat`.
///
/// The last assertion is the one the rest is scaffolding for. A `download_url`
/// naming a file that is not there is worse than no `download_url`: it tells a
/// caller the rest of its answer exists. The spill directory belongs to the
/// worker process and its destructor removes it, so the file is read *before*
/// the worker is cancelled.
///
/// [Measured] what the wire carries afterwards: a `content[0]` of 50,025
/// characters where the untrimmed rendering was 100,373, a `stdout` of 1,024
/// characters where the real one was 100,001, and a file of 100,315 characters
/// under `/tmp/bn-headless-mcp-output-<pid>-<uuid>/`.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_over_the_threshold_arrives_as_a_preview_and_the_rest_is_on_disk() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    let transport =
        TokioChildProcess::new(spawn(&["worker", "--input", &input])).expect("spawn worker");
    let worker = ().serve(transport).await.expect("worker initialize");

    // The control: the threshold is a ceiling for accidents, not a floor. Set
    // below what the ordinary tools produce, it replaces answers instead of
    // catching accidents. `binary.functions` with its default page is the
    // representative call here.
    let ordinary = worker
        .peer()
        .call_tool(CallToolRequestParams::new("binary.functions"))
        .await
        .expect("binary.functions");
    assert!(
        ordinary
            .meta
            .as_ref()
            .is_none_or(|meta| !meta.0.contains_key(META_KEY)),
        "an ordinary page tripped the net; the threshold is a ceiling, not a floor"
    );
    assert_eq!(
        ordinary.content.len(),
        1,
        "an answer that fit must not grow a hint block"
    );

    /// Characters the script prints. `print` adds one newline, so the string in
    /// the payload is one longer, and the assertions below say so.
    const PRINTED: usize = 100_000;
    let capped = worker
        .peer()
        .call_tool(
            CallToolRequestParams::new("script.python")
                .with_arguments(object(json!({"source": format!("print('A' * {PRINTED})")}))),
        )
        .await
        .expect("script.python");

    // Two blocks now: the shortened answer, and the sentence saying where the
    // rest of it went.
    assert_eq!(
        capped.content.len(),
        2,
        "a capped answer is the preview plus the hint"
    );
    let head = capped.content[0]
        .as_text()
        .expect("the first block is text")
        .text
        .clone();
    let head_chars = head.chars().count();
    let limits = Limits::default();
    assert!(
        head_chars <= limits.max_chars + 64,
        "the text block was not shortened: {head_chars} chars against a {} threshold",
        limits.max_chars
    );
    let tail: String = head.chars().skip(head_chars.saturating_sub(48)).collect();
    assert!(
        head.contains("chars total]"),
        "a shortened block has to say how much there was; it ends {tail:?}"
    );

    // The preview keeps the payload's shape, so it still validates against the
    // `outputSchema` the tool advertised — every key is there and only the one
    // unbounded string was cut.
    let preview = capped
        .structured_content
        .as_ref()
        .expect("script.python publishes structuredContent");
    assert_eq!(preview.get("ok"), Some(&json!(true)), "{preview:?}");
    assert_eq!(preview.get("timed_out"), Some(&json!(false)), "{preview:?}");
    assert_eq!(
        preview.get("truncated"),
        Some(&json!(false)),
        "script.python's own 256 KiB stdout cap must not be what cut this — the \
         output net is what is under test: {preview:?}"
    );
    let previewed = preview
        .get("stdout")
        .and_then(Value::as_str)
        .expect("script.python publishes stdout");
    assert!(
        previewed.chars().count() < PRINTED,
        "the structured payload was passed through whole"
    );
    assert!(
        previewed.ends_with(&format!("... [{} chars total]", PRINTED + 1)),
        "a cut string has to say how much was cut: {previewed:.64}"
    );

    let meta = capped
        .meta
        .as_ref()
        .and_then(|meta| meta.0.get(META_KEY))
        .expect("a capped answer carries `_meta.vibrev`")
        .clone();
    assert_eq!(meta.get("output_truncated"), Some(&json!(true)), "{meta:?}");
    let url = meta
        .get("download_url")
        .and_then(Value::as_str)
        .expect("`_meta.vibrev.download_url`");
    assert!(
        url.starts_with("file://"),
        "a worker speaks stdio to its supervisor and has no listener of its own, so \
         the only URL it can hand out is a file one: {url}"
    );

    // Read it here, while the worker that owns the directory is still alive.
    let path = file_path_of(url);
    let saved = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "`download_url` names {} and nothing can be read there: {e}",
            path.display()
        )
    });
    assert_eq!(
        meta.get("total_chars").and_then(Value::as_u64),
        Some(saved.chars().count() as u64),
        "`total_chars` does not describe what was actually saved"
    );
    let full: Value = serde_json::from_str(&saved).expect("the spill is the JSON payload");
    assert_eq!(
        full.get("stdout").and_then(Value::as_str),
        Some(format!("{}\n", "A".repeat(PRINTED)).as_str()),
        "the file holds a preview too — the part that was cut is nowhere"
    );

    worker.cancel().await.ok();
}

/// Read a `file://` URL back the way a client on this machine would: undo the
/// percent-encoding `vibrev_kit::output` applies, and take what is left as a
/// path.
fn file_path_of(url: &str) -> std::path::PathBuf {
    let encoded = url.strip_prefix("file://").expect("a file URL");
    let mut bytes = Vec::new();
    let mut chars = encoded.chars();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            bytes.push(u8::from_str_radix(&hex, 16).expect("a hex escape"));
        } else {
            bytes.push(ch as u8);
        }
    }
    std::path::PathBuf::from(String::from_utf8(bytes).expect("a UTF-8 path"))
}

/// `script.python` runs Binary Ninja's own Python against the view this worker
/// already holds. Three properties matter and only the MCP path can show them,
/// because each one needs two calls into the *same* process.
///
/// The CLI path is checked too, but not for byte equality: `elapsed_secs` is
/// wall clock, so the two paths cannot agree on it and it would be dishonest to
/// round it away just to make an assertion pass.
#[tokio::test(flavor = "multi_thread")]
async fn python_scripts_see_and_change_the_view_the_other_tools_read() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    let transport =
        TokioChildProcess::new(spawn(&["worker", "--input", &input])).expect("spawn worker");
    let worker = ().serve(transport).await.expect("worker initialize");

    let run = |source: &str| {
        let peer = worker.peer().clone();
        let source = source.to_owned();
        async move {
            peer.call_tool(
                CallToolRequestParams::new("script.python")
                    .with_arguments(object(json!({"source": source}))),
            )
            .await
            .expect("script.python is a successful response even when the script raises")
            .structured_content
            .expect("script.python publishes structuredContent")
        }
    };

    // 1. `bv` is this worker's view, not a freshly loaded one.
    let counted = run("result = len(list(bv.functions))").await;
    assert_eq!(counted.get("ok"), Some(&json!(true)), "{counted:?}");
    let from_python = counted.get("result").and_then(Value::as_u64).unwrap();
    let listed = worker
        .peer()
        .call_tool(
            CallToolRequestParams::new("binary.functions")
                .with_arguments(object(json!({"limit": 1}))),
        )
        .await
        .expect("binary.functions")
        .structured_content
        .expect("structuredContent");
    assert_eq!(
        Some(from_python),
        listed.get("total").and_then(Value::as_u64),
        "Python counted a different set of functions than binary.functions did"
    );

    // 2. The interpreter is one console: names survive between calls.
    let stored = run("marker = 'set by the first call'").await;
    assert_eq!(stored.get("ok"), Some(&json!(true)), "{stored:?}");
    let recalled = run("result = marker").await;
    assert_eq!(
        recalled.get("result"),
        Some(&json!("set by the first call")),
        "console state did not survive to the next call: {recalled:?}"
    );

    // 3. A write from Python is visible to the native tools immediately.
    let renamed = run("f = bv.get_function_at(bv.entry_point)\n\
         result = f.name\n\
         f.name = 'renamed_from_python'\n")
    .await;
    assert_eq!(renamed.get("ok"), Some(&json!(true)), "{renamed:?}");
    let found = worker
        .peer()
        .call_tool(
            CallToolRequestParams::new("binary.functions")
                .with_arguments(object(json!({"filter": "renamed_from_python"}))),
        )
        .await
        .expect("binary.functions")
        .structured_content
        .expect("structuredContent");
    assert_eq!(
        found.get("total"),
        Some(&json!(1)),
        "binary.functions cannot see the rename Python just made: {found:?}"
    );

    // 4. `script.reset` clears what the scripts defined but keeps `bv` bound.
    let reset = worker
        .peer()
        .call_tool(CallToolRequestParams::new("script.reset"))
        .await
        .expect("script.reset");
    assert_ne!(reset.is_error, Some(true), "{reset:?}");
    let gone = run("result = 'marker' in globals()").await;
    assert_eq!(
        gone.get("result"),
        Some(&json!(false)),
        "script.reset left the old namespace behind: {gone:?}"
    );
    let still_bound = run("result = bv is not None").await;
    assert_eq!(
        still_bound.get("result"),
        Some(&json!(true)),
        "script.reset unbound `bv`: {still_bound:?}"
    );

    worker.cancel().await.ok();
}

/// A raising script is a *successful* call reporting `ok: false` — not a
/// protocol error, and not an empty success either. Same for one that outlives
/// its timeout: the interrupt lands inside the script, so whatever it printed
/// before that point still comes back.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_script_reports_the_traceback_rather_than_erroring_out() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    let transport =
        TokioChildProcess::new(spawn(&["worker", "--input", &input])).expect("spawn worker");
    let worker = ().serve(transport).await.expect("worker initialize");

    let raised = worker
        .peer()
        .call_tool(
            CallToolRequestParams::new("script.python").with_arguments(object(
                json!({"source": "print('printed before the raise')\nraise ValueError('boom')"}),
            )),
        )
        .await
        .expect("a raising script is still a successful response")
        .structured_content
        .expect("structuredContent");
    assert_eq!(raised.get("ok"), Some(&json!(false)));
    assert_eq!(
        raised.get("stdout"),
        Some(&json!("printed before the raise\n")),
        "output produced before the exception must survive it"
    );
    assert!(
        raised
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|e| e.contains("ValueError: boom")),
        "the traceback must name the exception: {raised:?}"
    );

    // The console has to be usable after that.
    let after = worker
        .peer()
        .call_tool(
            CallToolRequestParams::new("script.python")
                .with_arguments(object(json!({"source": "result = 'still alive'"}))),
        )
        .await
        .expect("script.python")
        .structured_content
        .expect("structuredContent");
    assert_eq!(after.get("result"), Some(&json!("still alive")));

    // A script that will not finish is interrupted, and says so.
    let interrupted = worker
        .peer()
        .call_tool(
            CallToolRequestParams::new("script.python").with_arguments(object(json!({
                "source": "import time\nprint('starting')\nfor _ in range(600):\n    time.sleep(0.1)\n",
                "timeout_secs": 2
            }))),
        )
        .await
        .expect("script.python")
        .structured_content
        .expect("structuredContent");
    assert_eq!(interrupted.get("timed_out"), Some(&json!(true)));
    assert_eq!(interrupted.get("ok"), Some(&json!(false)));
    assert_eq!(
        interrupted.get("stdout"),
        Some(&json!("starting\n")),
        "output from before the interrupt must survive it"
    );

    // And the console survives the interrupt too.
    let recovered = worker
        .peer()
        .call_tool(
            CallToolRequestParams::new("script.python")
                .with_arguments(object(json!({"source": "result = 1 + 1"}))),
        )
        .await
        .expect("script.python")
        .structured_content
        .expect("structuredContent");
    assert_eq!(recovered.get("result"), Some(&json!(2)));

    worker.cancel().await.ok();
}

/// The type write path, checked for the property that justifies it: a type
/// written onto a function changes what `il.pseudo_c` renders.
///
/// Asserting only that the setter returns `ok: true` would pass on a tool that
/// wrote to nothing. The pseudocode is the observable, so that is what is
/// compared — before and after, in the same process, on the same view.
#[tokio::test(flavor = "multi_thread")]
async fn a_prototype_and_a_variable_change_what_pseudocode_renders() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    let transport =
        TokioChildProcess::new(spawn(&["worker", "--input", &input])).expect("spawn worker");
    let worker = ().serve(transport).await.expect("worker initialize");

    let call = |tool: &'static str, args: Map<String, Value>| {
        let peer = worker.peer().clone();
        async move {
            peer.call_tool(CallToolRequestParams::new(tool).with_arguments(args))
                .await
                .unwrap_or_else(|e| panic!("{tool}: {e}"))
        }
    };
    let structured = |tool: &'static str, args: Map<String, Value>| {
        let peer = worker.peer().clone();
        async move {
            let response = peer
                .call_tool(CallToolRequestParams::new(tool).with_arguments(args))
                .await
                .unwrap_or_else(|e| panic!("{tool}: {e}"));
            assert_ne!(response.is_error, Some(true), "{tool} failed: {response:?}");
            response
                .structured_content
                .unwrap_or_else(|| panic!("{tool} publishes no structuredContent"))
        }
    };

    // `sub_402040` has no symbol-derived signature, so anything the prototype
    // adds is visibly the prototype's doing.
    const TARGET: &str = "sub_402040";
    let pseudo = |args: Map<String, Value>| call("il.pseudo_c", args);
    let before = only_text(
        pseudo(object(json!({"target": TARGET}))).await,
        "il.pseudo_c",
    );

    let prototype = structured(
        "type.set_function_prototype",
        object(json!({
            "target": TARGET,
            "prototype": "int32_t probe(char *path, uint32_t flags)"
        })),
    )
    .await;
    assert_eq!(prototype.get("ok"), Some(&json!(true)), "{prototype:?}");
    assert_ne!(
        prototype.get("before"),
        prototype.get("after"),
        "the signature did not change: {prototype:?}"
    );

    let after = only_text(
        pseudo(object(json!({"target": TARGET}))).await,
        "il.pseudo_c",
    );
    assert_ne!(
        before, after,
        "the prototype was accepted but pseudocode is unchanged — the type went nowhere"
    );
    assert!(
        after.contains("path") && after.contains("flags"),
        "the new parameter names are not in the pseudocode:\n{after}"
    );

    // A variable rename has to be visible in `function.variables` *and* in the
    // pseudocode, and it has to stop being auto-defined.
    //
    // `path` is renamed rather than whichever variable happens to sort first:
    // this function's body references almost nothing, so a rename of an unused
    // local would be invisible in the rendering for a reason that has nothing to
    // do with whether the write worked. A parameter is always printed.
    let listed = structured("function.variables", object(json!({"target": TARGET}))).await;
    let names: Vec<&str> = listed
        .get("variables")
        .and_then(Value::as_array)
        .map(|v| v.iter().filter_map(|e| e["name"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        names.contains(&"path"),
        "the prototype's parameter is not among the function's variables: {names:?}"
    );

    let set = structured(
        "function.set_variable",
        object(json!({
            "target": TARGET,
            "variable": "path",
            "new_name": "renamed_by_the_test"
        })),
    )
    .await;
    assert_eq!(
        set.get("after").and_then(|a| a.get("name")),
        Some(&json!("renamed_by_the_test")),
        "{set:?}"
    );
    assert_eq!(
        set.get("after").and_then(|a| a.get("auto_defined")),
        Some(&json!(false)),
        "a user rename must stop the variable being auto-defined: {set:?}"
    );
    assert_eq!(
        set.get("before").and_then(|b| b.get("type")),
        set.get("after").and_then(|a| a.get("type")),
        "renaming must not change the type: {set:?}"
    );

    let renamed = only_text(
        pseudo(object(json!({"target": TARGET}))).await,
        "il.pseudo_c",
    );
    assert!(
        renamed.contains("renamed_by_the_test"),
        "the renamed variable is not in the pseudocode:\n{renamed}"
    );

    // Setting neither side is a caller error, not a silent no-op.
    let neither = call(
        "function.set_variable",
        object(json!({"target": TARGET, "variable": "renamed_by_the_test"})),
    )
    .await;
    assert_eq!(
        neither.is_error,
        Some(true),
        "set_variable with nothing to set must be an error: {neither:?}"
    );

    worker.cancel().await.ok();
}

/// A function's comment and a comment at an address are different objects, and
/// the two tools must not read each other's writes.
#[tokio::test(flavor = "multi_thread")]
async fn function_comments_and_address_comments_stay_apart() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    let transport =
        TokioChildProcess::new(spawn(&["worker", "--input", &input])).expect("spawn worker");
    let worker = ().serve(transport).await.expect("worker initialize");

    let structured = |tool: &'static str, args: Map<String, Value>| {
        let peer = worker.peer().clone();
        async move {
            let response = peer
                .call_tool(CallToolRequestParams::new(tool).with_arguments(args))
                .await
                .unwrap_or_else(|e| panic!("{tool}: {e}"));
            assert_ne!(response.is_error, Some(true), "{tool} failed: {response:?}");
            response
                .structured_content
                .unwrap_or_else(|| panic!("{tool} publishes no structuredContent"))
        }
    };

    structured(
        "annotation.set_function_comment",
        object(json!({"target": "main", "comment": "on the function"})),
    )
    .await;
    structured(
        "annotation.set_comment",
        object(json!({"target": "main", "comment": "at the address"})),
    )
    .await;

    let on_function = structured(
        "annotation.get_function_comment",
        object(json!({"target": "main"})),
    )
    .await;
    let at_address = structured("annotation.get_comment", object(json!({"target": "main"}))).await;
    assert_eq!(on_function.get("comment"), Some(&json!("on the function")));
    assert_eq!(at_address.get("comment"), Some(&json!("at the address")));

    // Clearing one must not clear the other.
    structured(
        "annotation.set_function_comment",
        object(json!({"target": "main", "comment": ""})),
    )
    .await;
    let cleared = structured(
        "annotation.get_function_comment",
        object(json!({"target": "main"})),
    )
    .await;
    let untouched = structured("annotation.get_comment", object(json!({"target": "main"}))).await;
    assert_eq!(cleared.get("comment"), Some(&json!("")));
    assert_eq!(
        untouched.get("comment"),
        Some(&json!("at the address")),
        "clearing the function comment also cleared the address comment"
    );

    worker.cancel().await.ok();
}

/// Patching, and the two ways a patch outlives the process.
///
/// The round trip is the point. A patch tool that reports `ok: true` and loses
/// the change on close is worse than no patch tool, so this writes a `.bndb`,
/// opens it in a **second worker**, and reads the bytes back there — and does
/// the same for the exported binary, which has to come back as a loadable file
/// with the patch in it.
#[tokio::test(flavor = "multi_thread")]
async fn patches_survive_a_bndb_and_an_exported_binary() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    // Not `/tmp`: this workspace runs on a tmpfs that is routinely near full,
    // and a `.bndb` is not small.
    let scratch = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(scratch).expect("scratch dir");
    let bndb = scratch.join("patched.bndb");
    let exported = scratch.join("patched.bin");
    let _ = std::fs::remove_file(&bndb);
    let _ = std::fs::remove_file(&exported);

    // `push rbp` at the top of a function: one byte, always patchable, and its
    // NOP is unambiguous.
    const ADDRESS: &str = "0x402040";
    const PATCHED_BYTE: &str = "90";

    let transport =
        TokioChildProcess::new(spawn(&["worker", "--input", &input])).expect("spawn worker");
    let worker = ().serve(transport).await.expect("worker initialize");

    let structured = |peer: rmcp::service::ServerSink,
                      tool: &'static str,
                      args: Map<String, Value>| async move {
        let response = peer
            .call_tool(CallToolRequestParams::new(tool).with_arguments(args))
            .await
            .unwrap_or_else(|e| panic!("{tool}: {e}"));
        assert_ne!(response.is_error, Some(true), "{tool} failed: {response:?}");
        response
            .structured_content
            .unwrap_or_else(|| panic!("{tool} publishes no structuredContent"))
    };

    // `patch.available` must agree with what `patch.nop` then does. Binary
    // Ninja's `IsNeverBranchPatchAvailable` answers `false` here and NOPing
    // works anyway, which is why `can_nop` is derived from the instruction
    // decoding rather than from that API.
    let available = structured(
        worker.peer().clone(),
        "patch.available",
        object(json!({"address": ADDRESS})),
    )
    .await;
    assert_eq!(
        available.get("can_nop"),
        Some(&json!(true)),
        "{available:?}"
    );
    assert_eq!(
        available.get("can_never_branch"),
        Some(&json!(false)),
        "`push rbp` is not a branch; can_never_branch must not claim otherwise: {available:?}"
    );
    assert_eq!(available.get("instruction_length"), Some(&json!(1)));

    let patched = structured(
        worker.peer().clone(),
        "patch.nop",
        object(json!({"address": ADDRESS})),
    )
    .await;
    assert_eq!(patched.get("ok"), Some(&json!(true)), "{patched:?}");
    assert_eq!(patched.get("bytes_after"), Some(&json!(PATCHED_BYTE)));
    assert_ne!(
        patched.get("listing_before"),
        patched.get("listing_after"),
        "the bytes changed but the disassembly did not — the view was not re-analyzed"
    );

    // Both persistence paths, from the same patched view.
    let saved = structured(
        worker.peer().clone(),
        "database.create_bndb",
        object(json!({"path": bndb.to_string_lossy()})),
    )
    .await;
    assert_eq!(saved.get("created"), Some(&json!(true)), "{saved:?}");

    let dumped = structured(
        worker.peer().clone(),
        "database.export_binary",
        object(json!({"path": exported.to_string_lossy()})),
    )
    .await;
    assert_eq!(dumped.get("written"), Some(&json!(true)), "{dumped:?}");

    worker.cancel().await.ok();

    // A second process, so nothing in the first one's memory can carry the
    // answer.
    for (label, path) in [
        ("bndb", bndb.to_string_lossy().into_owned()),
        ("exported binary", exported.to_string_lossy().into_owned()),
    ] {
        let transport = TokioChildProcess::new(spawn(&["worker", "--input", &path]))
            .unwrap_or_else(|e| panic!("spawn worker on the {label}: {e}"));
        let reopened = ().serve(transport).await.expect("worker initialize");
        let bytes = structured(
            reopened.peer().clone(),
            "memory.read",
            object(json!({"address": ADDRESS, "length": 1})),
        )
        .await;
        assert_eq!(
            bytes.get("hex"),
            Some(&json!(PATCHED_BYTE)),
            "the patch did not survive the {label}: {bytes:?}"
        );
        reopened.cancel().await.ok();
    }

    let _ = std::fs::remove_file(&bndb);
    let _ = std::fs::remove_file(&exported);
}

/// `patch.revert` undoes a patch, one whole patch at a time, and refuses when
/// the newest change is not a patch.
///
/// Both halves are the design. Binary Ninja's undo stack is per-file and
/// last-in-first-out over *every* edit, so a revert tool that just calls undo
/// would answer "revert my patch" by taking back a rename. And a patch that
/// writes twice — `patch.assemble` writes an encoding and then its NOP padding —
/// has to come back in one call or the view is left in a state nobody asked for.
#[tokio::test(flavor = "multi_thread")]
async fn reverting_takes_back_one_whole_patch_and_nothing_else() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    let transport =
        TokioChildProcess::new(spawn(&["worker", "--input", &input])).expect("spawn worker");
    let worker = ().serve(transport).await.expect("worker initialize");

    let raw = |tool: &'static str, args: Map<String, Value>| {
        let peer = worker.peer().clone();
        async move {
            peer.call_tool(CallToolRequestParams::new(tool).with_arguments(args))
                .await
                .unwrap_or_else(|e| panic!("{tool}: {e}"))
        }
    };
    let structured = |tool: &'static str, args: Map<String, Value>| {
        let peer = worker.peer().clone();
        async move {
            let response = peer
                .call_tool(CallToolRequestParams::new(tool).with_arguments(args))
                .await
                .unwrap_or_else(|e| panic!("{tool}: {e}"));
            assert_ne!(response.is_error, Some(true), "{tool} failed: {response:?}");
            response
                .structured_content
                .unwrap_or_else(|| panic!("{tool} publishes no structuredContent"))
        }
    };

    // A 6-byte `jne`, so assembling `nop` over it writes 1 byte plus 5 of
    // padding — two writes, one patch.
    const WIDE: &str = "0x4025f6";
    let before = structured("memory.read", object(json!({"address": WIDE, "length": 6}))).await;
    let original = before
        .get("hex")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();

    let assembled = structured(
        "patch.assemble",
        object(json!({"address": WIDE, "code": "nop"})),
    )
    .await;
    assert_eq!(
        assembled.get("padding_bytes"),
        Some(&json!(5)),
        "{assembled:?}"
    );
    assert_eq!(assembled.get("bytes_after"), Some(&json!("909090909090")));

    let reverted = structured("patch.revert", Map::new()).await;
    assert_eq!(reverted.get("ok"), Some(&json!(true)), "{reverted:?}");
    let restored = structured("memory.read", object(json!({"address": WIDE, "length": 6}))).await;
    assert_eq!(
        restored.get("hex").and_then(Value::as_str),
        Some(original.as_str()),
        "the encoding came back but the padding did not — the patch was more than \
         one undo entry: {reverted:?}"
    );

    // Now the refusal. Patch, then rename, then ask to revert the patch.
    const NARROW: &str = "0x402040";
    let patched = structured("patch.nop", object(json!({"address": NARROW}))).await;
    assert_eq!(
        patched.get("bytes_after"),
        Some(&json!("90")),
        "{patched:?}"
    );

    structured(
        "annotation.rename_function",
        object(json!({"target": "main", "new_name": "renamed_after_the_patch"})),
    )
    .await;

    let refused = raw("patch.revert", Map::new()).await;
    assert_eq!(
        refused.is_error,
        Some(true),
        "reverting must refuse when the newest change is a rename: {refused:?}"
    );
    let still_patched = structured(
        "memory.read",
        object(json!({"address": NARROW, "length": 1})),
    )
    .await;
    assert_eq!(
        still_patched.get("hex"),
        Some(&json!("90")),
        "the refusal was not free — something was undone anyway"
    );
    let name_kept = structured(
        "binary.functions",
        object(json!({"filter": "renamed_after_the_patch"})),
    )
    .await;
    assert_eq!(
        name_kept.get("total"),
        Some(&json!(1)),
        "the rename was undone by a call that said it refused: {name_kept:?}"
    );

    worker.cancel().await.ok();
}

/// Backgrounding, against a real supervisor: a background `session.open`
/// answers with a protocol handle, and what that handle settles to is the answer
/// the synchronous call would have given.
///
/// The last clause is what makes this belong in this file rather than beside
/// it. Backgrounding is a second way out of `call_tool`, and a second way out is
/// exactly where a second renderer appears — the failure mode this suite exists
/// for. So the terminal payload is compared byte for byte against a synchronous
/// `session.open` of the same path, run first, in the same process.
///
/// Everything here needs a client that negotiated MCP 2026-07-28 *and* the
/// tasks capability, which is why it builds a `ClientInfo` rather than using
/// `()`: the default client declares neither, and this engine refuses to hand a
/// handle to a peer that could not poll it.
#[tokio::test(flavor = "multi_thread")]
async fn a_backgrounded_open_settles_to_the_answer_the_blocking_one_gives() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    let transport =
        TokioChildProcess::new(spawn(&["serve", "--mode", "stdio"])).expect("spawn supervisor");
    let supervisor = task_capable_client()
        .serve(transport)
        .await
        .expect("supervisor initialize");
    let peer = supervisor.peer().clone();

    // Twice, and the second one is the baseline. The first open *creates* the
    // view and says `reused: false`; every later one reuses it and says
    // `reused: true`. Comparing the background call against the cold open would
    // be comparing two different true answers — the difference this test is for
    // is rendering, so both sides have to be warm.
    let CallToolResponse::Complete(_) = open_call(&peer, &input, false).await else {
        panic!("a call without `background` must not answer with a handle");
    };
    let CallToolResponse::Complete(blocking) = open_call(&peer, &input, false).await else {
        panic!("a call without `background` must not answer with a handle");
    };
    let blocking = only_text(blocking, "session.open");

    let CallToolResponse::Task(handle) = open_call(&peer, &input, true).await else {
        panic!("a task-capable client asking for `background` must get a handle");
    };
    assert_eq!(
        handle.task.poll_interval_ms,
        Some(500),
        "the engine's poll interval did not reach the wire; the kit's 5 s default is \
         wrong for a load measured in seconds"
    );

    let settled = poll_until_settled(&peer, &handle.task.task_id).await;
    let TaskPayload::Completed { result } = settled.payload else {
        panic!("the background open did not complete: {settled:?}");
    };
    let result: CallToolResult = serde_json::from_value(Value::Object(result))
        .expect("a completed task carries the CallToolResult the tool produced");
    assert_eq!(
        only_text(result, "session.open"),
        blocking,
        "the background path rendered its own answer instead of carrying the tool's"
    );

    supervisor.cancel().await.ok();
}

/// Cancelling an open takes back the view it created — and only that view.
///
/// A cancel that reports success while a Binary Ninja worker keeps a license
/// seat is the same class of failure as a patch tool that reports `ok: true` and
/// loses the change on close. `session.list` is the observable, so that is what
/// is checked, from the same connection, after the task reaches a terminal
/// state.
#[tokio::test(flavor = "multi_thread")]
async fn cancelling_an_open_closes_the_view_it_opened() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    let transport =
        TokioChildProcess::new(spawn(&["serve", "--mode", "stdio"])).expect("spawn supervisor");
    let supervisor = task_capable_client()
        .serve(transport)
        .await
        .expect("supervisor initialize");
    let peer = supervisor.peer().clone();

    let CallToolResponse::Task(handle) = open_call(&peer, &input, true).await else {
        panic!("expected a handle");
    };
    peer.cancel_task(CancelTaskParams::new(handle.task.task_id.clone()))
        .await
        .expect("cancel is acknowledged");

    let settled = poll_until_settled(&peer, &handle.task.task_id).await;
    assert_eq!(settled.status(), TaskStatus::Cancelled, "{settled:?}");

    let list = peer
        .call_tool(CallToolRequestParams::new("session.list"))
        .await
        .expect("session.list");
    let views = list
        .structured_content
        .expect("session.list is structured")
        .get("total")
        .and_then(Value::as_u64)
        .expect("a total");
    assert_eq!(
        views, 0,
        "the cancelled open left a worker holding a license seat"
    );

    supervisor.cancel().await.ok();
}

/// A client that cannot hold a handle is told so, rather than handed one.
///
/// This is the whole reason this engine ships no `task_status` tool: the only
/// other options were a handle with no verb able to poll it, or silently
/// ignoring a parameter the caller typed.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_without_the_tasks_capability_is_refused_not_stranded() {
    let _serial = exclusive().await;
    let Some(input) = requirements() else { return };

    let transport =
        TokioChildProcess::new(spawn(&["serve", "--mode", "stdio"])).expect("spawn supervisor");
    // `()` is the default client: no tasks capability, older protocol.
    let supervisor = ().serve(transport).await.expect("supervisor initialize");

    let CallToolResponse::Complete(refused) = open_call(supervisor.peer(), &input, true).await
    else {
        panic!("a client that cannot poll must not be handed a handle");
    };
    assert_eq!(refused.is_error, Some(true));
    let text = only_text(refused, "session.open");
    assert!(text.contains("2026-07-28"), "{text}");
    assert!(text.contains("background"), "{text}");

    // And nothing was started behind its back.
    let list = supervisor
        .peer()
        .call_tool(CallToolRequestParams::new("session.list"))
        .await
        .expect("session.list");
    assert_eq!(
        list.structured_content
            .expect("structured")
            .get("total")
            .and_then(Value::as_u64),
        Some(0),
        "the refusal opened a view anyway"
    );

    supervisor.cancel().await.ok();
}

/// A peer that declares MCP 2026-07-28 and the tasks capability — the only kind
/// this engine will hand a task handle to.
fn task_capable_client() -> ClientInfo {
    ClientInfo::new(
        ClientCapabilities::builder().enable_tasks().build(),
        Implementation::from_build_env(),
    )
    .with_protocol_version(ProtocolVersion::V_2026_07_28)
}

async fn open_call(peer: &Peer<RoleClient>, input: &str, background: bool) -> CallToolResponse {
    let mut args = object(json!({"path": input}));
    if background {
        args.insert("background".to_owned(), json!(true));
    }
    // `call_tool_once` rather than `call_tool`: the high-level helper drives
    // SEP-2322 rounds and therefore returns a settled `CallToolResult`, which is
    // the one shape that cannot show whether a handle was issued.
    peer.call_tool_once(CallToolRequestParams::new("session.open").with_arguments(args))
        .await
        .expect("session.open is routed")
}

/// Poll at the cadence the server asked for, and give up well before the test
/// harness would — a hang here should read as a stuck task, not as a timeout.
async fn poll_until_settled(peer: &Peer<RoleClient>, task_id: &str) -> DetailedTask {
    for _ in 0..240 {
        let got = peer
            .get_task(GetTaskParams::new(task_id))
            .await
            .expect("tasks/get is routed");
        if got.task.task.status != TaskStatus::Working {
            return got.task;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    panic!("{task_id} never left `working`");
}
