//! `bn-headless-mcp` — Binary Ninja as a complete, self-contained MCP server,
//! with a CLI derived from the same tool definitions and mounted under `tool`.
//!
//! Three entry points:
//!
//! * `serve` — the supervisor. Behind a listener by default, and over stdio on
//!   `--mode stdio`; one command because it is one server, and the transport is
//!   the only thing that differs. On the listener every request carries a bearer
//!   token; there is no flag that turns that off, because
//!   `vibrev_kit::transport` has no parameter for it. Does not initialize Binary
//!   Ninja itself; it spawns workers.
//! * `worker --input <PATH>` — one Binary Ninja `Session` holding one
//!   `BinaryView`, speaking MCP on stdio. Normally spawned by `serve`, but it is
//!   a plain MCP server and can be connected to directly.
//! * `tool <name> --input <PATH>` — run a single tool and exit. Same function
//!   bodies, same renderer, same bytes.
//!
//! `doctor` reports whether this machine can run any of them.

use std::io::IsTerminal;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use rmcp::transport::stdio;
use rmcp::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

mod bn;
mod error;
mod policy;
mod server;
mod supervisor;
// Test-only: the tool-surface contract this engine is checked against, not
// something it implements. See `src/surface.rs`.
#[cfg(test)]
mod surface;

use bn::Engine;
use server::BnMcpServer;
use supervisor::Supervisor;
use vibrev_kit::output::{Capped, OutputCache};
use vibrev_kit::policy::{Governed, PolicyArgs, ToolPolicy};

/// Root-level commands this engine handles itself.
///
/// Handed to the kit through `with_management` so the tool-name check runs
/// against what is really registered. A guessed `RESERVED` list cannot know
/// about `worker`, and `<engine> tool worker …` reading as the management command
/// is exactly the ambiguity the check is for.
const MANAGEMENT_COMMANDS: &[&str] = &["serve", "worker", "doctor"];

/// The one command that can open a listener, named once so `cli_command` and
/// `main` cannot disagree about where the kit's flags were hung.
const SERVE_COMMAND: &str = "serve";

/// The session slot, declared once.
///
/// `selector: Some("view")` names the property the *supervisor* injects into
/// every routed tool. The derived CLI drops it and fills the slot from `--input`
/// instead, because a one-shot process has exactly one view and asking the caller
/// to name it would be asking for something only the server knows.
///
/// `ready: None` because there is nothing to wait for separately: Binary Ninja's
/// load takes `update_analysis_and_wait = true` and does not return until
/// analysis has converged, so the wait is *inside* the open, there is nothing to
/// poll, and there is no opting out of a wait that already happened.
static SESSION: vibrev_kit::session::SessionSpec = vibrev_kit::session::SessionSpec {
    selector: Some(supervisor::VIEW_PARAM),
    flag: "input",
    value_name: "PATH",
    help: "要打开的二进制或 .bndb（工具在它上面执行）",
    missing: "Binary Ninja 的工具都读一个已打开的 BinaryView，\
              而 CLI 是一次性进程，必须先知道打开哪个",
    ready: None,
};

#[derive(Parser)]
#[command(
    name = "bn-headless-mcp",
    about = "Binary Ninja as an MCP server, with the same tools on the command line",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the MCP server (default; HTTP unless --mode stdio)
    Serve(ServeArgs),
    /// Run one Binary Ninja worker over stdio. Normally spawned by `serve`.
    Worker(WorkerArgs),
    /// Report whether this machine can run Binary Ninja headlessly.
    Doctor,
}

/// Which transport `serve` speaks.
///
/// Both arms run the same supervisor over the same worker processes, publish the
/// same catalogue, and apply the same policy; only the framing differs.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[value(rename_all = "lowercase")]
enum ServeMode {
    /// Streamable HTTP on a listening socket.
    #[default]
    Http,
    /// JSON-RPC over this process's stdin/stdout.
    Stdio,
}

/// `serve`'s own arguments — which is to say, the transport and nothing else.
///
/// One field, and that is not an omission. `ida-headless-mcp` carries a pool of
/// child databases here and needs flags to size it; this engine holds one view
/// per worker process and has no pool, so there is no knob to expose.
///
/// The listener knobs — bind, token, Host, framing, body cap — are not
/// here either. They belong to `vibrev_kit::transport::HttpOptions`, which
/// [`cli_command`] hangs on this same subcommand as plain `Arg`s, so that this
/// engine and `ida-headless-mcp` cannot spell `--bind` two ways.
#[derive(clap::Args, Debug, Clone)]
struct ServeArgs {
    /// Transport to serve on.
    #[arg(long, value_enum, default_value_t = ServeMode::Http)]
    mode: ServeMode,
}

impl Default for ServeArgs {
    /// The bare invocation (`bn-headless-mcp` with no subcommand) never enters
    /// clap's subcommand parsing, so it needs these values from somewhere.
    /// Taking them from clap itself — rather than repeating the literals here —
    /// is what stops `bn-headless-mcp` and `bn-headless-mcp serve` from drifting
    /// into two servers that only look alike.
    fn default() -> Self {
        #[derive(Parser)]
        struct Bare {
            #[command(flatten)]
            serve: ServeArgs,
        }

        Bare::parse_from(["serve"]).serve
    }
}

#[derive(clap::Args)]
struct WorkerArgs {
    /// Binary or .bndb this worker holds for its whole life.
    #[arg(long)]
    input: String,
}

/// Refuse a listener flag that `--mode stdio` cannot honour.
///
/// The alternative is the thing merging the two commands exists to remove: a
/// flag that parses, reads as configuration, and does nothing. Both spellings of
/// that are worse than an error — `--bind` missing from `serve` entirely would
/// make it untypable on the transport that *does* honour it, and `--bind`
/// accepted-and-ignored under stdio is a silent lie. Refusing by name is the
/// third option.
///
/// Two things this deliberately does not do. It does not keep its own list of
/// listener flag names: the names come out of the kit's own `Arg` set, so a
/// tenth flag added to `HttpOptions` is refused here the day it lands rather
/// than slipping through because this file had never heard of it. And it counts
/// only `ValueSource::CommandLine`: every one of these flags carries a default
/// or may carry an env var, and aborting a server over a value the caller never
/// typed — a default, or something exported once for a whole environment —
/// would be refusing an invocation the flag was not aimed at.
fn reject_listener_flags_on_stdio(serve: Option<&clap::ArgMatches>) -> anyhow::Result<()> {
    // A bare invocation never enters `serve`, and it cannot reach stdio anyway.
    let Some(serve) = serve else {
        return Ok(());
    };
    let given = |id: &str| serve.value_source(id) == Some(clap::parser::ValueSource::CommandLine);
    let mut named: Vec<String> = vibrev_kit::transport::HttpOptions::args()
        .iter()
        .filter(|arg| given(arg.get_id().as_str()))
        .filter_map(|arg| arg.get_long().map(|long| format!("--{long}")))
        .collect();
    if named.is_empty() {
        return Ok(());
    }
    named.sort();
    Err(anyhow::anyhow!(
        "{} {} no meaning with --mode stdio (there is no listener to configure); \
         drop {} or run --mode http",
        named.join(", "),
        if named.len() == 1 { "has" } else { "have" },
        if named.len() == 1 { "it" } else { "them" },
    ))
}

/// Graft the derived tool tree onto the hand-written root.
///
/// `#[derive(Parser)]` builds this binary's own commands; the kit builds the
/// `tool` subtree from the same `Tool` structs the MCP surface publishes. They
/// meet here, and the kit checks every tool name against `MANAGEMENT_COMMANDS`
/// while it does so.
fn cli_command() -> clap::Command {
    let derived = BnMcpServer::vibrev_cli("bn-headless-mcp")
        .with_management(MANAGEMENT_COMMANDS)
        .with_session(&SESSION)
        .command();
    let tools = derived
        .find_subcommand(vibrev_kit::cli::TOOL_COMMAND)
        .expect("the kit always builds a `tool` subcommand")
        .clone();
    let cmd = <Cli as clap::CommandFactory>::command()
        // Builder-side rather than a `#[command(flatten)]` field: the kit owns
        // the names and the help text so that three engines cannot spell
        // `--read-only` three ways, and it hands them over as `Arg`s. They are
        // `global(true)`, which is what puts their values in the leaf matches
        // `cli::resolve` returns — the `tool` path never parses this root.
        .args(vibrev_kit::policy::PolicyArgs::args())
        // Not global, unlike the policy flags: `--bind` means nothing to
        // `worker` or `tool`, so it hangs on `serve`, the only command that can
        // listen. Note "can": `serve` also has `--mode stdio`, which cannot
        // honour any of these. That case is handled by
        // [`reject_listener_flags_on_stdio`] refusing the flag by name, not by
        // withholding it here — a flag hung on a narrower command would be one
        // the transport that does honour it could no longer be given.
        .mut_subcommand(SERVE_COMMAND, |serve| {
            serve.args(vibrev_kit::transport::HttpOptions::args())
        })
        .subcommand(tools);
    // `with_management` only feeds the collision check, which runs before this
    // Parser tree is grafted on. The closed loop is here: declared names and
    // the finished clap root must agree.
    vibrev_kit::cli::assert_management_matches_command(&cmd, MANAGEMENT_COMMANDS);
    cmd
}

fn main() -> anyhow::Result<()> {
    // stdout belongs to JSON-RPC framing in every mode, so all logging goes to
    // stderr — including in `tool` mode, where stdout carries the tool's answer
    // and nothing else.
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("bn_headless_mcp=info")),
        )
        .init();

    let matches = cli_command().get_matches();
    // Read before the `resolve` early-return, because that branch never reaches
    // `Cli::from_arg_matches` and the flags are global on every level.
    let selection = vibrev_kit::policy::PolicyArgs::read(&matches);
    if let Some((name, leaf)) = vibrev_kit::cli::resolve(&matches) {
        return run_tool(name, leaf, &selection);
    }

    let cli = <Cli as clap::FromArgMatches>::from_arg_matches(&matches)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    match cli
        .command
        .unwrap_or_else(|| Command::Serve(ServeArgs::default()))
    {
        Command::Serve(args) => {
            // The listener flags hang on `serve` rather than on the root: they
            // mean nothing to `worker` or `tool`, so unlike the policy flags
            // they are not `global(true)` and have to be read from that level.
            //
            // A bare invocation never enters the subcommand, so there is no such
            // level to read — and that is the whole contract of the bare form:
            // it means "a working listener with nothing configured", and
            // configuring anything means typing `serve`.
            let serve = matches.subcommand_matches(SERVE_COMMAND);
            match args.mode {
                ServeMode::Http => {
                    let http = match serve {
                        Some(leaf) => vibrev_kit::transport::HttpOptions::read(leaf),
                        // Spelled out rather than handing the root matches to
                        // `read`: that would also yield the defaults, but only
                        // because the root never registered these flags — an
                        // accident that reads like a decision. This says the
                        // decision.
                        None => vibrev_kit::transport::HttpOptions::default(),
                    };
                    runtime.block_on(run_supervisor_http(&selection, &http))
                }
                // Before the transport comes up, not after: a refused flag
                // should cost nothing and leave nothing running.
                ServeMode::Stdio => {
                    reject_listener_flags_on_stdio(serve)?;
                    runtime.block_on(run_supervisor_stdio(&selection))
                }
            }
        }
        Command::Worker(args) => runtime.block_on(run_worker(&args.input, &selection)),
        Command::Doctor => doctor(),
    }
}

/// Say on stderr what a policy narrowed, counted through the policy itself.
///
/// Announced rather than silent: a client that sees thirty tools where the
/// documentation lists forty-seven cannot tell a filter from a bug, and the
/// operator who passed the flag is the one reading this stream. Counting by
/// running the catalog through `advertise` rather than tracking a number
/// alongside it means the log cannot disagree with what the client gets.
fn announce<T: vibrev_kit::Advertised + Clone>(policy: &ToolPolicy, catalog: &[T]) {
    if !policy.is_active() {
        return;
    }
    let advertised = policy.advertise(catalog.to_vec()).len();
    tracing::info!(
        "tool policy active: advertising {advertised} of {} tools",
        catalog.len()
    );
}

async fn run_supervisor_stdio(selection: &PolicyArgs) -> anyhow::Result<()> {
    let supervisor = Supervisor::new()?;
    // Built against the supervisor's own catalog, which carries the four
    // `session.*` primitives the worker face does not have.
    let catalog = supervisor::supervisor_tools();
    let policy = policy::build(&catalog, selection)?;
    announce(&policy, &catalog);
    let service = Governed::new(supervisor.clone(), Arc::new(policy))
        .serve(stdio())
        .await?;
    service.waiting().await?;
    // Asked to stop before the drop below takes their workers out from under
    // them, so a task that is mid-`session.open` settles as cancelled rather
    // than as a worker that stopped answering.
    supervisor.cancel_background_tasks("Cancelled by client disconnect");
    // Every worker dies with this process: the session table drops, each
    // `RunningService` drops, and `kill_on_drop` finishes the job.
    Ok(())
}

/// What a caller holding the token reaches through this port.
///
/// A listener hands whoever holds the token everything the policy still allows,
/// so the banner **says so, every start**. Hiding `script.python` behind a
/// default-off switch is not the alternative: a capability withheld by default
/// is one an operator discovers through "why does this not work", and
/// `--exclude-tools script.python` is already the way to say no. So the banner
/// names it and says how to turn it off in the same breath.
///
/// Read off the live policy rather than hard-coded, so an operator who did
/// exclude it is not told their listener runs code it will refuse to run.
fn exposure(policy: &ToolPolicy) -> vibrev_kit::transport::Exposure {
    let mut reach = vec![
        "a caller holding the token can open any file on this host for \
         analysis (reading arbitrary files is what this tool does)"
            .to_string(),
    ];
    if policy.allows("database.save") || policy.allows("database.export_binary") {
        reach.push("and can write analysed or patched copies back to disk".to_string());
    }
    vibrev_kit::transport::Exposure {
        engine: "bn-headless-mcp",
        routes: &["/mcp"],
        reach,
        arbitrary_code: policy.allows("script.python").then(|| {
            "script.python runs caller-supplied Python inside a worker; \
             --exclude-tools script.python removes it"
                .to_string()
        }),
    }
}

/// The supervisor behind a listener.
///
/// Same server, same policy, same catalogue as [`run_supervisor_stdio`] — only the
/// transport differs, and the transport is entirely `vibrev_kit::transport`.
/// Note what is absent: no bind loop, no token handling, no `Host`
/// check, and no `.layer(...)` on the router. The kit takes the router and puts
/// the gate over all of it, so a route added here later cannot be left
/// unguarded by forgetting a line at this call site.
async fn run_supervisor_http(
    selection: &PolicyArgs,
    http: &vibrev_kit::transport::HttpOptions,
) -> anyhow::Result<()> {
    let catalog = supervisor::supervisor_tools();
    let policy = Arc::new(policy::build(&catalog, selection)?);
    announce(&policy, &catalog);

    // Establishes the credential before it binds: a token file we cannot read is
    // fatal, and doing it the other way round would leave a port open while the
    // failure is being reported.
    let listener = vibrev_kit::transport::Listener::bind(http).await?;
    eprintln!(
        "{}",
        listener.banner(&exposure(&policy), std::io::stderr().is_terminal())
    );
    for note in listener.token_notes() {
        eprintln!(" {note}");
    }

    let supervisor = Supervisor::new()?;
    let sessions = vibrev_kit::transport::session_manager(http.session_keep_alive_secs);
    let config = listener.config().clone();
    let factory = supervisor.clone();
    let service = rmcp::transport::streamable_http_server::StreamableHttpService::new(
        // `http_face` rather than `clone`: the handler has to know which face it
        // is answering on, because that is the whole of the task-owner rule. It
        // runs per POST, not per connection — rmcp dispatches every 2026-07-28
        // request statelessly — so it must stay a cheap shallow clone.
        move || Ok(Governed::new(factory.http_face(), policy.clone())),
        sessions,
        config,
    );
    listener
        .serve(axum::Router::new().route_service("/mcp", service))
        .await?;
    supervisor.cancel_background_tasks("Cancelled by server shutdown");
    // Every worker dies with this process, the same way it does on stdio: the
    // session table drops, each `RunningService` drops, `kill_on_drop` finishes.
    Ok(())
}

async fn run_worker(input: &str, selection: &PolicyArgs) -> anyhow::Result<()> {
    // The policy is built before the binary is opened: a selection that cannot
    // be satisfied should fail in milliseconds, not after a full analysis pass.
    //
    // The supervisor does not pass these flags down when it spawns a worker, so
    // this applies to a worker started by hand. Reaching a spawned worker's
    // stdio already means being the process that spawned it, which is why the
    // supervisor's own policy is the one that governs routed calls.
    let catalog = BnMcpServer::vibrev_tool_defs();
    let policy = policy::build(&catalog, selection)?;
    announce(&policy, &catalog);

    // Load before the transport comes up. A worker that cannot open its binary
    // must fail visibly here rather than accept an `initialize` and then answer
    // every call with the same error.
    let engine = Arc::new(Engine::open(input)?);
    // The output net goes here rather than on the supervisor, for two reasons.
    // The supervisor forwards a worker's `CallToolResult` verbatim and that is a
    // guarantee worth keeping; and this is where an oversized answer is
    // produced, so catching it here means ten megabytes of pseudocode never
    // cross the pipe between the two processes at all.
    //
    // Files rather than a URL: a worker speaks stdio to its supervisor and has
    // no listener of its own. The spill lives as long as the worker does, which
    // is as long as the view is open — closing a view takes its outputs with it.
    let outputs = OutputCache::spilling_to_files("bn-headless-mcp")?;
    let service = Capped::new(
        Governed::new(BnMcpServer::new(engine), Arc::new(policy)),
        outputs,
    )
    .serve(stdio())
    .await?;
    service.waiting().await?;
    Ok(())
}

/// Run one derived tool and exit.
///
/// Same shape as `worker` minus the transport: open the view, call the tool,
/// print, exit. Binary Ninja is never shut down — the process ending is what
/// releases it, because dropping the last `Session` calls `BNShutdown` and the
/// next `Session::new()` never returns (Binary Ninja upstream issue #6660).
///
/// There is no output cap on this path, unlike `worker`: the answer goes into a
/// pipe, not into a model's context window, so truncating it here would answer a
/// question nobody asked.
fn run_tool(name: String, leaf: &clap::ArgMatches, selection: &PolicyArgs) -> anyhow::Result<()> {
    let defs = BnMcpServer::vibrev_tool_defs();
    let Some(def) = defs.iter().find(|d| d.name() == name) else {
        anyhow::bail!("unknown tool: {name}");
    };

    // The policy governs this path too: the flags are `global(true)`, so
    // `bn tool patch.nop --read-only` parses, and a flag a user can type that
    // then does nothing is worse than one that is not offered.
    if !policy::build(&defs, selection)?.allows(&name) {
        anyhow::bail!("{name} 已被当前策略排除（--toolsets/--tools/--exclude-tools/--read-only）");
    }

    // `--json-input` carries what flags cannot express. No tool needs it today —
    // none has an object-typed parameter — but the branch is the kit's contract,
    // not this engine's, and leaving it out is how it stops working silently.
    let args = match leaf.try_get_one::<String>("__json_input").ok().flatten() {
        Some(path) => {
            let raw = if path == "-" {
                std::io::read_to_string(std::io::stdin())?
            } else {
                std::fs::read_to_string(path)?
            };
            serde_json::from_str(&raw)?
        }
        None => match vibrev_kit::cli::to_arguments(def, leaf) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(2);
            }
        },
    };

    let session = match SESSION.read(leaf) {
        Ok(session) => session,
        Err(missing) => {
            eprintln!("Error: {missing}");
            std::process::exit(2);
        }
    };
    let as_json = leaf.get_flag("__json");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let code = runtime.block_on(async move {
        let engine = Arc::new(Engine::open(&session.target)?);
        let server = BnMcpServer::new(engine);
        // The same body `tools/call` reaches, converted by the same
        // `IntoCallToolResult` the router uses — so `outcome.text` is not a
        // second rendering that agrees with `content[0]`, it *is* `content[0]`.
        let outcome = server
            .vibrev_call(&name, args)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.message))?;
        let text = if as_json {
            outcome.json_text()
        } else {
            outcome.text.clone()
        };
        if outcome.is_error {
            // The tool ran and reported failure: `isError: true` over MCP, exit
            // code plus stderr here.
            eprintln!("{text}");
            return Ok::<i32, anyhow::Error>(1);
        }
        println!("{text}");
        Ok(0)
    })?;
    std::process::exit(code);
}

/// Report what this machine can and cannot do, without loading anything.
///
/// Distribution is source-only (see README), so the failure modes are all
/// environmental: no `BINARYNINJADIR`, no license, wrong edition. Each line says
/// what to do about it rather than only what is wrong.
fn doctor() -> anyhow::Result<()> {
    println!("bn-headless-mcp {}", env!("CARGO_PKG_VERSION"));
    println!(
        "built against Binary Ninja API commit {}",
        bn::PINNED_API_REVISION
    );

    match std::env::var("BINARYNINJADIR") {
        Ok(dir) => println!("BINARYNINJADIR = {dir}"),
        Err(_) => println!(
            "BINARYNINJADIR is unset — it is only needed to *build*; this binary already \
             carries the core's path in its rpath."
        ),
    }

    // `license_location` is a pure lookup with no core initialization, so doctor
    // still answers on a machine that could not actually run a session.
    match binaryninja::headless::license_location() {
        Some(location) => println!("license: found via {location:?}"),
        None => println!(
            "license: NOT FOUND — headless Binary Ninja needs a Commercial or Ultimate \
             license. Set BN_LICENSE to the license text (`export \
             BN_LICENSE=\"$(cat ~/bn-license.txt)\"`), or put license.dat in the Binary \
             Ninja user directory."
        ),
    }
    println!("max concurrent calls per view: {}", bn::MAX_INFLIGHT);
    println!("tools: {}", supervisor::supervisor_tools().len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_from(args: &[&str]) -> ToolPolicy {
        let matches = cli_command()
            .get_matches_from(std::iter::once("bn-headless-mcp").chain(args.iter().copied()));
        policy::build(&supervisor::supervisor_tools(), &PolicyArgs::read(&matches)).expect("policy")
    }

    /// Parse a full argv through the real command tree and hand back what
    /// `main` would dispatch on. `Cli::parse_from` would not do: the listener
    /// flags are grafted on in `cli_command` and `Cli` alone has never heard of
    /// them.
    fn serve_args(argv: &[&str]) -> ServeArgs {
        let matches = cli_command().get_matches_from(argv);
        let Command::Serve(args) = <Cli as clap::FromArgMatches>::from_arg_matches(&matches)
            .expect("root parses")
            .command
            .expect("subcommand")
        else {
            panic!("expected serve")
        };
        args
    }

    /// The listener names what it hands to whoever holds the token.
    ///
    /// The answer to `script.python` on a port is not to hide the tool — a
    /// capability withheld by default is one an operator meets as "why does this
    /// not work" — but to name it on every start, next to the way to remove it.
    /// If this assertion ever goes quiet, the banner stopped saying that.
    #[test]
    fn the_banner_names_code_execution_and_how_to_turn_it_off() {
        let exposure = exposure(&policy_from(&["serve"]));
        let named = exposure
            .arbitrary_code
            .expect("script.python is advertised");
        assert!(named.contains("script.python"));
        assert!(named.contains("--exclude-tools script.python"));
        assert!(exposure.reach.iter().any(|line| line.contains("any file")));
    }

    /// And it must not claim more than it does: an operator who excluded the
    /// tool should not be told their listener runs code it will refuse to run.
    #[test]
    fn excluding_the_script_tool_takes_it_out_of_the_banner_too() {
        let excluded = exposure(&policy_from(&["--exclude-tools", "script.python", "serve"]));
        assert!(excluded.arbitrary_code.is_none());

        let read_only = exposure(&policy_from(&["--read-only", "serve"]));
        assert!(read_only.arbitrary_code.is_none(), "script.python writes");
        assert!(
            !read_only
                .reach
                .iter()
                .any(|line| line.contains("back to disk")),
            "--read-only removes database.save/export_binary"
        );
    }

    /// The listener has no off switch, and `serve` is the level a user would
    /// look for one at now that it is the command that listens. `vibrev-kit`
    /// asserts the same over its own `Arg`s; this covers the grafting, which is
    /// where such a flag would have to reappear to take effect.
    #[test]
    fn serve_offers_no_way_to_drop_the_credential() {
        let mut command = cli_command();
        let rendered = command
            .find_subcommand_mut(SERVE_COMMAND)
            .expect("serve")
            .render_long_help()
            .to_string();
        for absent in ["--no-auth", "--insecure", "--anonymous", "--no-token"] {
            assert!(!rendered.contains(absent), "{absent} is offered");
        }
        assert!(rendered.contains("--token-file"));
        assert!(rendered.contains("--bind"));
    }

    /// The listener flags belong to the kit and hang on `serve`, so a wiring
    /// mistake would show up as `HttpOptions::read` quietly returning defaults
    /// that only look right.
    #[test]
    fn the_listener_flags_reach_the_subcommand_that_uses_them() {
        let matches = cli_command().get_matches_from([
            "bn-headless-mcp",
            "serve",
            "--bind",
            "127.0.0.1:19998",
        ]);
        let http = vibrev_kit::transport::HttpOptions::read(
            matches
                .subcommand_matches(SERVE_COMMAND)
                .expect("serve matches"),
        );
        assert_eq!(http.bind.to_string(), "127.0.0.1:19998");
        assert_eq!(http.session_keep_alive_secs, 1800);
    }

    /// HTTP is what `serve` does unless told otherwise. This is the line the
    /// merge moved: `serve` used to mean stdio.
    #[test]
    fn http_is_the_default_transport() {
        assert_eq!(
            serve_args(&["bn-headless-mcp", "serve"]).mode,
            ServeMode::Http
        );
        assert_eq!(
            serve_args(&["bn-headless-mcp", "serve", "--mode", "stdio"]).mode,
            ServeMode::Stdio
        );
    }

    /// The bare invocation does not go through clap's subcommand parsing, so its
    /// values come from `ServeArgs::default`. If that ever stops agreeing with
    /// the clap-declared ones, `bn-headless-mcp` and `bn-headless-mcp serve`
    /// become two different servers that look alike — which is exactly why
    /// `Default` reads the values back out of clap instead of restating them.
    #[test]
    fn a_bare_invocation_serves_what_an_explicit_serve_would() {
        let explicit = serve_args(&["bn-headless-mcp", "serve"]);
        let bare = ServeArgs::default();

        assert_eq!(bare.mode, explicit.mode);

        // The listener side of the same promise: a bare invocation has no
        // `serve` matches to read, and the defaults it falls back to are the
        // ones an explicit `serve` would have parsed.
        let matches = cli_command().get_matches_from(["bn-headless-mcp", "serve"]);
        let parsed = vibrev_kit::transport::HttpOptions::read(
            matches
                .subcommand_matches(SERVE_COMMAND)
                .expect("serve matches"),
        );
        let fallback = vibrev_kit::transport::HttpOptions::default();
        assert_eq!(parsed.bind, fallback.bind);
        assert_eq!(parsed.bind.to_string(), "127.0.0.1:8765");
        assert_eq!(parsed.allow_host, fallback.allow_host);
        assert_eq!(parsed.token_file, fallback.token_file);
        assert_eq!(parsed.sse_keep_alive_secs, fallback.sse_keep_alive_secs);
        assert_eq!(
            parsed.session_keep_alive_secs,
            fallback.session_keep_alive_secs
        );
        assert_eq!(parsed.stateless, fallback.stateless);
        assert_eq!(parsed.json_response, fallback.json_response);
        assert_eq!(parsed.max_request_body_mib, fallback.max_request_body_mib);
    }

    /// A listener flag under `--mode stdio` is refused by name, not ignored.
    /// Silently accepting it is the defect this merge exists to remove.
    #[test]
    fn a_listener_flag_is_refused_on_stdio() {
        let matches = cli_command().get_matches_from([
            "bn-headless-mcp",
            "serve",
            "--mode",
            "stdio",
            "--bind",
            "0.0.0.0:9000",
        ]);
        let error = reject_listener_flags_on_stdio(matches.subcommand_matches(SERVE_COMMAND))
            .expect_err("--bind must be refused under --mode stdio");
        let message = error.to_string();
        // Both halves matter: which flag, and what it is incompatible with.
        assert!(message.contains("--bind"), "{message}");
        assert!(message.contains("--mode stdio"), "{message}");
    }

    /// The other half of the refusal: it counts only what was typed. Every
    /// listener flag with a `default_value` is *present* in the matches of every
    /// `serve --mode stdio`, so a check that looked at presence rather than
    /// `ValueSource::CommandLine` would refuse the plain stdio invocation —
    /// which is to say, all of them.
    ///
    /// `ValueSource::EnvVariable` is the same rule and the same branch, but it
    /// cannot arise here: this engine does not enable clap's `env` feature, so
    /// no listener flag can carry one. (`ida-headless-mcp` hangs
    /// `IDA_MCP_TOKEN_FILE` on `--token-file` and covers that case there.)
    #[test]
    fn a_value_the_caller_did_not_type_does_not_refuse_stdio() {
        let matches =
            cli_command().get_matches_from(["bn-headless-mcp", "serve", "--mode", "stdio"]);
        let leaf = matches
            .subcommand_matches(SERVE_COMMAND)
            .expect("serve matches");
        // Not a vacuous pass: `--bind` really is in these matches, carrying a
        // value that simply did not come from the command line.
        assert_eq!(
            leaf.value_source(vibrev_kit::transport::BIND_ARG),
            Some(clap::parser::ValueSource::DefaultValue)
        );
        reject_listener_flags_on_stdio(Some(leaf))
            .expect("a default the caller never typed is not a listener flag they passed");
    }

    /// And the bare invocation, which has no `serve` matches at all, is let
    /// through rather than panicking on a level that was never parsed.
    #[test]
    fn a_bare_invocation_has_no_listener_flags_to_refuse() {
        let matches = cli_command().get_matches_from(["bn-headless-mcp"]);
        assert!(matches.subcommand_matches(SERVE_COMMAND).is_none());
        reject_listener_flags_on_stdio(matches.subcommand_matches(SERVE_COMMAND))
            .expect("nothing was typed, so nothing can be refused");
    }

    /// The root holds management commands and the `tool` entry, and nothing
    /// else.
    #[test]
    fn the_root_holds_management_commands_plus_the_tool_subtree() {
        let cmd = cli_command();
        let mut names: Vec<String> = cmd
            .get_subcommands()
            .map(|c| c.get_name().to_owned())
            .collect();
        names.sort();
        let mut expected: Vec<String> = MANAGEMENT_COMMANDS
            .iter()
            .map(|s| (*s).to_owned())
            .chain(std::iter::once(vibrev_kit::cli::TOOL_COMMAND.to_owned()))
            .collect();
        expected.sort();
        assert_eq!(names, expected);
    }

    /// The reverse assertion: a declared management command that no longer
    /// exists on the tree is drift the kit cannot see.
    #[test]
    fn every_declared_management_command_really_exists() {
        let cmd = cli_command();
        for name in MANAGEMENT_COMMANDS {
            assert!(
                cmd.find_subcommand(name).is_some(),
                "{name} is declared to the kit but not registered with clap"
            );
        }
    }

    /// A cheap smoke test in place of a full consistency check: one leaf under
    /// `tool` per tool on the MCP surface.
    #[test]
    fn the_tool_subtree_has_one_leaf_per_tool() {
        let cmd = cli_command();
        let tool = cmd
            .find_subcommand(vibrev_kit::cli::TOOL_COMMAND)
            .expect("tool subtree");
        let leaves: usize = tool
            .get_subcommands()
            .filter(|group| group.get_name() != "help")
            .map(|group| {
                let children = group
                    .get_subcommands()
                    .filter(|c| c.get_name() != "help")
                    .count();
                if children == 0 {
                    1
                } else {
                    children
                }
            })
            .sum();
        assert_eq!(leaves, BnMcpServer::vibrev_tool_defs().len());
    }

    #[test]
    fn every_group_command_has_about_from_the_router() {
        let cmd = cli_command();
        let tool = cmd
            .find_subcommand(vibrev_kit::cli::TOOL_COMMAND)
            .expect("tool subtree");
        let groups = [
            "binary",
            "il",
            "disasm",
            "xref",
            "function",
            "annotation",
            "memory",
            "type",
            "database",
            "analyze",
        ];
        for name in groups {
            let about = tool
                .find_subcommand(name)
                .unwrap_or_else(|| panic!("missing group {name}"))
                .get_about()
                .map(ToString::to_string);
            assert!(
                about.as_ref().is_some_and(|s| !s.is_empty()),
                "group {name} is missing group_about, got {about:?}"
            );
        }
    }

    /// The session flag has to be reachable from a leaf, or `--input` could only
    /// be typed before the tool name.
    #[test]
    fn the_session_flag_is_global_across_the_tool_subtree() {
        let cmd = cli_command();
        let matches = cmd
            .try_get_matches_from([
                "bn-headless-mcp",
                "tool",
                "binary",
                "segments",
                "--input",
                "/bin/cat",
            ])
            .expect("the tool subtree accepts --input at the leaf");
        let (name, leaf) = vibrev_kit::cli::resolve(&matches).expect("a tool was named");
        assert_eq!(name, "binary.segments");
        assert_eq!(
            SESSION.read(leaf).expect("--input was given").target,
            "/bin/cat"
        );
    }
}
