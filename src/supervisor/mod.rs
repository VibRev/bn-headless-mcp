//! Session table plus worker pool — the process model this engine runs on.
//!
//! **Why processes at all.** Binary Ninja's `Session` cannot be re-initialized:
//! dropping the last one calls `BNShutdown`, and the next `Session::new()` hangs
//! (Binary Ninja upstream issue #6660; measured on this machine as a hang rather
//! than the segfault that issue reports, which is worse — no core dump, just a
//! request that never returns). There is therefore no in-process way to close a
//! view and get the memory back. A process per view makes "close" mean `kill`,
//! which does work.
//!
//! **Worker results are forwarded verbatim.** `content`, `structuredContent` and
//! `isError` cross this process untouched; nothing here rebuilds them from the
//! parsed value. That is what makes the guarantee end to end — the bytes an MCP
//! client receives are the bytes `bn-headless-mcp tool …` prints. Re-rendering
//! anywhere on this path breaks it, even from the same `serde_json::Value` and
//! even with the same renderer, because the surface would then be one hop
//! removed from the one `tests/two_paths.rs` holds byte-identical.
//!
//! **The shape here is one view, one process: no pool, no leases, no main-thread
//! loop.** A view is opened by spawning a worker, closed by killing it, and
//! reclaimed by an idle reaper; concurrency within a view is a semaphore and
//! nothing else. That is worth stating because it is what makes this supervisor
//! a poor candidate for extraction into a shared layer. The part that looks
//! generic — a table of children, a routing key, kill-on-drop — is about thirty
//! lines of pattern; everything around it is a consequence of `BNShutdown` being
//! unrecoverable, which is why "close" is a process kill here rather than a
//! release back to a pool. A layer general enough to host both this and a pooled,
//! leased worker model would have to make process-per-view one of its
//! configurations, and that configuration would cost more than the thirty lines
//! it saved. Copy the pattern into the next engine that needs it; do not hoist
//! this file.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, CancelTaskParams, ContentBlock,
    GetTaskParams, GetTaskResult, ListToolsResult, PaginatedRequestParams, ServerCapabilities,
    ServerInfo, Tool, ToolAnnotations, UpdateTaskParams,
};
use rmcp::service::{Peer, RequestContext, RoleClient, RoleServer, RunningService};
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::{ErrorData, ServerHandler, ServiceExt};
use serde_json::{json, Map, Value};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::info;
use vibrev_kit::tasks::{peer_can_hold_task_handle, TaskHost, TaskOwner, TaskRegistry};

use crate::bn::MAX_INFLIGHT;
use crate::error::ToolError;
use crate::server::{responses, BnMcpServer};

mod tasks;

use tasks::{Face, BACKGROUND_PARAM};

/// The one worker tool this supervisor will run in the background.
///
/// Named here rather than matched inline because two places have to agree about
/// it: the branch in `call_tool` and the schema graft in [`supervisor_tools`]. A
/// tool that advertises `background` and is then forwarded synchronously would
/// be the quiet kind of wrong.
const BACKGROUNDABLE_WORKER_TOOL: &str = "script.python";

/// Every tool that answers with a task handle, in the order they are advertised.
///
/// Three things read this: the routing check in `call_tool`, the refusal it
/// produces for anything else, and the test that holds it against the published
/// schemas. The two slow calls this engine has are a Binary Ninja load and an
/// arbitrary Python script; everything else answers in milliseconds once the
/// view is open, and a handle for those would be a round trip charged for
/// nothing.
const BACKGROUNDABLE: &[&str] = &[BACKGROUNDABLE_WORKER_TOOL, "session.open"];

/// The schema property every routed tool grows: `view`, never a shared
/// `database` and never an implicit current object.
pub const VIEW_PARAM: &str = "view";

/// Tools the supervisor answers itself rather than forwarding.
pub const SESSION_TOOLS: &[&str] = &[
    "session.open",
    "session.list",
    "session.close",
    "health.ping",
];

/// Seconds a view may sit unused before the reaper closes it.
///
/// `0` disables reaping, and workers then live until `session.close` or
/// supervisor exit. Default is 1800 (30 minutes): load is expensive, but an
/// idle worker holds a license seat and hundreds of MB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdleTtl {
    secs: u64,
}

impl IdleTtl {
    const DEFAULT_SECS: u64 = 1800;
    const ENV: &'static str = "BN_IDLE_TTL_SECS";
    const DEFAULT: Self = Self {
        secs: Self::DEFAULT_SECS,
    };

    fn from_env() -> Self {
        match std::env::var(Self::ENV) {
            Ok(raw) => raw.parse().unwrap_or(Self::DEFAULT),
            Err(_) => Self::DEFAULT,
        }
    }

    fn from_secs(secs: u64) -> Self {
        Self { secs }
    }

    fn disabled(self) -> bool {
        self.secs == 0
    }

    /// Wake often enough that a short TTL is not delayed by a 30 s tick, and
    /// rarely enough that a 30-minute TTL does not poll every second.
    fn poll_interval(self) -> Duration {
        Duration::from_secs(self.secs.min(30))
    }

    fn duration(self) -> Duration {
        Duration::from_secs(self.secs)
    }
}

impl FromStr for IdleTtl {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self::from_secs)
    }
}

/// Why a view was or was not selected for idle reclaim. The reaper and the
/// unit tests share [`idle_reap_decision`] so these four cases cannot drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdleReapDecision {
    /// `BN_IDLE_TTL_SECS=0`: never reclaim.
    TtlDisabled,
    /// Idle, but shorter than the TTL.
    NotYetIdle,
    /// Idle at least `ttl` and no inflight call: close it.
    Idle,
    /// Would be past the TTL, but a forwarded call holds a permit.
    InflightBusy,
}

impl IdleReapDecision {
    fn should_reap(self) -> bool {
        match self {
            Self::Idle => true,
            Self::TtlDisabled | Self::NotYetIdle | Self::InflightBusy => false,
        }
    }
}

/// Pure reap decision. `ttl == 0` wins over everything else, so disabling the
/// reaper really does mean never closing a view — including one that has been
/// idle for hours. Inflight work is never treated as idle: `last_used` is the
/// call start, so a long tool call can outlive the TTL without being dead.
fn idle_reap_decision(ttl: IdleTtl, idle_for: Duration, inflight: usize) -> IdleReapDecision {
    if ttl.disabled() {
        return IdleReapDecision::TtlDisabled;
    }
    if inflight > 0 {
        return IdleReapDecision::InflightBusy;
    }
    if idle_for >= ttl.duration() {
        IdleReapDecision::Idle
    } else {
        IdleReapDecision::NotYetIdle
    }
}

struct ManagedView {
    id: String,
    input_path: String,
    pid: Option<u32>,
    peer: Peer<RoleClient>,
    /// Kept so that dropping the entry kills the child (`kill_on_drop`).
    service: Mutex<Option<RunningService<RoleClient, ()>>>,
    /// [Measured] Binary Ninja's analysis speedup is 3.83x on 8 threads, so more
    /// than four concurrent calls buys nothing and costs CPU analysis needs.
    inflight: Arc<Semaphore>,
    opened_at: Instant,
    /// Last open or forwarded call, not `opened_at`: a view that is being
    /// used must not be killed for having been loaded a long time ago.
    last_used: std::sync::Mutex<Instant>,
}

impl ManagedView {
    fn info(&self) -> responses::ViewInfo {
        responses::ViewInfo {
            view: self.id.clone(),
            input_path: self.input_path.clone(),
            pid: self.pid,
            age_secs: self.opened_at.elapsed().as_secs(),
            inflight: self.inflight_count(),
        }
    }

    fn touch(&self) {
        *self.lock_last_used() = Instant::now();
    }

    fn lock_last_used(&self) -> std::sync::MutexGuard<'_, Instant> {
        self.last_used.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(*self.lock_last_used())
    }

    fn inflight_count(&self) -> usize {
        MAX_INFLIGHT.saturating_sub(self.inflight.available_permits())
    }

    /// True while nothing has touched this view since it was created.
    ///
    /// Stronger than `inflight_count() == 0`, and that is the point: a caller
    /// who was handed this view by a *reusing* `session.open` holds it without
    /// having a call in flight, and `open` touches on reuse exactly so that this
    /// can be seen. Used by the cancelled-open cleanup to tell "the view I made
    /// and nobody ever saw" from "the view I made and somebody now depends on".
    fn untouched_since_open(&self) -> bool {
        *self.lock_last_used() == self.opened_at
    }
}

/// The supervisor: owns the session table, spawns and reaps workers, routes
/// calls. It never links a `Session` of its own, so a worker crash cannot take
/// it down. Unused views are closed after 1800 s of no forwarded calls
/// (`BN_IDLE_TTL_SECS`; `0` disables reaping).
#[derive(Clone)]
pub struct Supervisor {
    views: Arc<RwLock<BTreeMap<String, Arc<ManagedView>>>>,
    next_id: Arc<AtomicU64>,
    /// Serializes `session.open`, so two concurrent opens of one path cannot each
    /// pay 1.6 s of Binary Ninja startup for a view one of them will discard.
    open_lock: Arc<Mutex<()>>,
    worker_exe: std::path::PathBuf,
    idle_ttl: IdleTtl,
    /// Shared by every clone, so the HTTP face's per-session (and per-request)
    /// handlers all read one table.
    tasks: TaskRegistry,
    /// Parent of every background task's cancellation token, cancelled once, at
    /// shutdown.
    ///
    /// Process-scoped, not connection-scoped, and it has to be: rmcp dispatches
    /// MCP-2026 requests sessionless *even on a session-managed listener* — and
    /// MCP-2026 clients are exactly the ones that can hold a task handle, so a
    /// token hung on the handler would be dropped, and the task cancelled, the
    /// instant the response went out. Tying it to the process is also the honest
    /// model for what these tasks produce: a view belongs to the session table,
    /// not to the caller who opened it, and the idle reaper is what reclaims an
    /// abandoned one.
    lifetime: CancellationToken,
    face: Face,
    session_owner: TaskOwner,
}

impl Supervisor {
    pub fn new() -> anyhow::Result<Self> {
        let supervisor = Self {
            views: Arc::new(RwLock::new(BTreeMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            open_lock: Arc::new(Mutex::new(())),
            worker_exe: std::env::current_exe()?,
            idle_ttl: IdleTtl::from_env(),
            tasks: TaskRegistry::new(),
            lifetime: CancellationToken::new(),
            face: Face::Stdio,
            session_owner: tasks::new_session_owner(),
        };
        supervisor.spawn_idle_reaper();
        Ok(supervisor)
    }

    /// The same supervisor, answering on the listening face.
    ///
    /// Everything is shared — session table, worker pool, task registry, task
    /// lifetime — because the listener's factory runs this **per POST**, not per
    /// connection: rmcp dispatches every request at protocol 2026-07-28
    /// statelessly, and those are exactly the requests that can hold a task
    /// handle. Anything a handler owned privately would therefore be born and
    /// die inside one request, which is why the inherited `session_owner` is
    /// carried but never consulted here (see [`tasks::Face`]) — on this face
    /// every task belongs to `TaskOwner::Runtime`.
    pub fn http_face(&self) -> Self {
        Self {
            face: Face::Http,
            ..self.clone()
        }
    }

    /// Ask every running background task to stop, on the way out.
    ///
    /// A request, not a kill: the kit keeps a task `Running` until the work it
    /// wraps actually settles, because a thread parked inside Binary Ninja's
    /// core cannot be interrupted by anything this process owns.
    pub fn cancel_background_tasks(&self, why: &str) {
        self.lifetime.cancel();
        let requested = self.tasks.cancel_all_running(why);
        if requested > 0 {
            info!(requested, why, "requested background task cancellation");
        }
    }

    /// Holds only a `Weak` to the session table so dropping the last
    /// `Supervisor` still drops every worker. A strong clone here would keep
    /// idle processes alive after `serve` returned.
    fn spawn_idle_reaper(&self) {
        if self.idle_ttl.disabled() {
            return;
        }
        let views = Arc::downgrade(&self.views);
        let ttl = self.idle_ttl;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(ttl.poll_interval());
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // `interval` fires immediately; nothing can be idle yet.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(views) = views.upgrade() else {
                    break;
                };
                reap_idle_views(&views, ttl).await;
            }
        });
    }

    async fn open(&self, path: &str) -> Result<responses::OpenResult, ToolError> {
        let _guard = self.open_lock.lock().await;

        // Compare by canonical path: `./cat` and `/bin/cat` are the same binary,
        // and paying for a second Binary Ninja process to learn that is the kind
        // of thing a caller never sees and always pays for.
        let canonical = std::fs::canonicalize(path)
            .map_err(|e| ToolError::InvalidParams(format!("cannot open {path}: {e}")))?
            .to_string_lossy()
            .into_owned();
        if let Some(existing) = self
            .views
            .read()
            .await
            .values()
            .find(|v| v.input_path == canonical)
            .cloned()
        {
            existing.touch();
            return Ok(responses::OpenResult {
                view: existing.id.clone(),
                input_path: existing.input_path.clone(),
                pid: existing.pid,
                reused: true,
                message: format!(
                    "{canonical} is already open as {}; reusing it rather than paying for a \
                     second Binary Ninja process.",
                    existing.id
                ),
            });
        }

        let id = format!("bnv_{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let mut cmd = tokio::process::Command::new(&self.worker_exe);
        cmd.arg("worker").arg("--input").arg(&canonical);
        // The supervisor's lifetime is the client's, and a worker outliving it
        // would hold a Binary Ninja license and a few hundred MB with nobody to
        // talk to.
        cmd.kill_on_drop(true);

        let (transport, stderr) = TokioChildProcess::builder(cmd)
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ToolError::Worker(format!("could not spawn a worker for {path}: {e}")))?;
        let pid = transport.id();
        if let Some(stderr) = stderr {
            relay_stderr(id.clone(), stderr);
        }

        // A worker that cannot load its binary exits during initialize, so this
        // is where a bad path or a missing license surfaces — with the worker's
        // own stderr already on ours.
        let service = ().serve(transport).await.map_err(|e| {
            ToolError::Worker(format!(
                "worker for {canonical} did not start: {e}. Its stderr is on this process's \
                 stderr; a missing BN_LICENSE is the usual cause."
            ))
        })?;

        let now = Instant::now();
        let view = Arc::new(ManagedView {
            id: id.clone(),
            input_path: canonical.clone(),
            pid,
            peer: service.peer().clone(),
            service: Mutex::new(Some(service)),
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            opened_at: now,
            last_used: std::sync::Mutex::new(now),
        });
        self.views.write().await.insert(id.clone(), view);
        info!(view = %id, path = %canonical, ?pid, "opened view");

        Ok(responses::OpenResult {
            view: id,
            input_path: canonical,
            pid,
            reused: false,
            message: "Analysis has already settled: the worker loads with \
                      update_analysis_and_wait, so the first answer is the converged one."
                .to_owned(),
        })
    }

    async fn list(&self) -> responses::ViewList {
        let views: Vec<responses::ViewInfo> =
            self.views.read().await.values().map(|v| v.info()).collect();
        responses::ViewList {
            total: views.len(),
            views,
        }
    }

    async fn close(&self, id: &str) -> Result<responses::CloseResult, ToolError> {
        close_view(&self.views, id).await
    }

    /// Whether `id` is still open and still untouched since it was created.
    ///
    /// A fresh read of the table rather than a value carried from the open: the
    /// question is about *now*, and the answer changes under us.
    async fn untouched_since_open(&self, id: &str) -> bool {
        self.views
            .read()
            .await
            .get(id)
            .is_some_and(|view| view.untouched_since_open())
    }

    /// Supervisor liveness. Reads the session table; does not initialize Binary Ninja.
    async fn health(&self) -> responses::Health {
        responses::Health {
            status: "ok".to_owned(),
            open_views: self.views.read().await.len(),
            tools: supervisor_tools().len(),
            max_inflight_per_view: MAX_INFLIGHT,
            message: "The supervisor is up and does not initialize Binary Ninja; \
                      session.open starts a worker."
                .to_owned(),
        }
    }

    /// Forward one call to the worker that owns `view`, verbatim.
    async fn forward(
        &self,
        view_id: &str,
        tool: &str,
        args: Map<String, Value>,
    ) -> Result<CallToolResult, ToolError> {
        let view = self
            .views
            .read()
            .await
            .get(view_id)
            .cloned()
            .ok_or_else(|| {
                ToolError::NotFound(format!(
                    "no such view: {view_id}. Open one with session.open, or call \
                     session.list to see what is open."
                ))
            })?;

        // Touch before the call so a just-used view is not selected while we
        // wait for a permit, and after so a tool call longer than the TTL does
        // not look idle the instant it returns.
        view.touch();
        let _permit = view
            .inflight
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ToolError::Worker("view is closing".to_owned()))?;
        let response = view
            .peer
            .call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(args))
            .await;
        view.touch();
        response.map_err(|e| {
            ToolError::Worker(format!(
                "worker holding {view_id} failed to answer {tool}: {e}"
            ))
        })
    }
}

/// Drop the service, kill the child, Session reclaimed — same path as
/// `session.close`. The idle reaper uses this so a TTL expiry cannot skip the
/// kill-on-drop that is the only way memory comes back (#6660).
async fn close_view(
    views: &RwLock<BTreeMap<String, Arc<ManagedView>>>,
    id: &str,
) -> Result<responses::CloseResult, ToolError> {
    let Some(view) = views.write().await.remove(id) else {
        return Err(ToolError::NotFound(format!(
            "no such view: {id}. Call session.list to see what is open."
        )));
    };
    // Dropping the service closes the pipe; `kill_on_drop` handles a worker
    // that is wedged inside Binary Ninja and will not notice EOF. Process
    // exit is the only thing that gives the memory back (#6660).
    let service = view.service.lock().await.take();
    drop(service);
    info!(view = %id, "closed view");
    Ok(responses::CloseResult {
        view: id.to_owned(),
        closed: true,
        message: "Worker process terminated; Binary Ninja's memory is released by the OS."
            .to_owned(),
    })
}

async fn reap_idle_views(views: &RwLock<BTreeMap<String, Arc<ManagedView>>>, ttl: IdleTtl) {
    let now = Instant::now();
    let ids: Vec<String> = {
        let table = views.read().await;
        table
            .values()
            .filter(|view| {
                idle_reap_decision(ttl, view.idle_for(now), view.inflight_count()).should_reap()
            })
            .map(|view| view.id.clone())
            .collect()
    };
    for id in ids {
        // A call may have arrived between the snapshot and now; re-check so we
        // do not kill a worker that just became busy.
        let now = Instant::now();
        let reap = {
            let table = views.read().await;
            match table.get(&id) {
                Some(view) => {
                    idle_reap_decision(ttl, view.idle_for(now), view.inflight_count()).should_reap()
                }
                None => false,
            }
        };
        if !reap {
            continue;
        }
        if close_view(views, &id).await.is_ok() {
            info!(view = %id, "reaped idle view");
        }
    }
}

fn relay_stderr(id: String, stderr: tokio::process::ChildStderr) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            // Worker diagnostics must reach the operator; stdout belongs to
            // JSON-RPC framing in every mode, so they go to stderr.
            eprintln!("[{id}] {line}");
        }
    });
}

/// The supervisor's advertised tool list: the worker's tools with a `view`
/// parameter grafted on, plus the session primitives.
///
/// Grafting rather than redeclaring is what keeps the two surfaces from
/// drifting: descriptions, annotations and output schemas all come from the same
/// `#[vibrev_tool]` attributes the worker and the CLI were built from, and a new
/// tool appears here without anyone editing this file.
pub fn supervisor_tools() -> Vec<Tool> {
    let mut tools: Vec<Tool> = session_tools();
    for def in BnMcpServer::vibrev_tool_defs() {
        let mut tool = def.tool.clone();
        let mut schema = (*tool.input_schema).clone();
        let props = schema
            .entry("properties")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("schema properties is an object");
        props.insert(
            VIEW_PARAM.to_owned(),
            json!({
                "type": "string",
                "description":
                    "The view handle returned by session.open. Required: this server holds \
                     several binaries at once and has no notion of a current one.",
            }),
        );
        // Grafted here rather than declared on the worker, for the same reason
        // `view` is: it is the supervisor that acts on it. The worker publishes
        // no `background` and is never sent one — it runs the script the way it
        // always has, and this process is what stops waiting.
        if tool.name == BACKGROUNDABLE_WORKER_TOOL {
            props.insert(
                BACKGROUND_PARAM.to_owned(),
                tasks::background_property(
                    "Cancelling the handle does not interrupt a running script — it was \
                     already submitted, and settles on its own timeout_secs.",
                ),
            );
        }
        let required = schema
            .entry("required")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("schema required is an array");
        required.push(json!(VIEW_PARAM));
        tool.input_schema = Arc::new(schema);
        tools.push(tool);
    }
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    tools
}

fn annotations(title: &str, read_only: bool, destructive: bool) -> ToolAnnotations {
    ToolAnnotations::with_title(title)
        .read_only(read_only)
        .destructive(destructive)
        .idempotent(true)
        .open_world(false)
}

/// The supervisor's own four tools.
///
/// Hand-built, so nothing normalizes their schemas on the way in the way
/// `#[vibrev_tool]` does for the other 47 — `Tool::with_output_schema` hands
/// schemars' product straight through, `$schema` and all. The kit's normalizer
/// is applied here for exactly that reason: these four are advertised next to
/// the derived ones and a client has no way to know which is which.
fn session_tools() -> Vec<Tool> {
    let mut tools = raw_session_tools();
    for tool in &mut tools {
        vibrev_kit::schema::normalize_tool(tool);
    }
    tools
}

fn raw_session_tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "session.open",
            "Open a binary (or a .bndb) and return the view handle every analysis tool \
             takes. Loading runs Binary Ninja's analysis to completion before returning, so \
             the first answer is already the converged one — expect seconds, not \
             milliseconds. Opening a path that is already open returns the existing handle.",
            Arc::new(object_schema(
                &[
                    (
                        "path",
                        json!({
                            "type": "string",
                            "description": "Filesystem path to the binary or .bndb.",
                        }),
                    ),
                    (
                        BACKGROUND_PARAM,
                        tasks::background_property(
                            "Cancelling the handle closes the view the open created, unless \
                             the path was already open — that view belongs to whoever opened \
                             it first and is left alone.",
                        ),
                    ),
                ],
                &["path"],
            )),
        )
        .with_title("Open a binary")
        .with_output_schema::<responses::OpenResult>()
        // Not read-only: it starts a process and takes a license seat.
        .with_annotations(annotations("Open a binary", false, false)),
        Tool::new(
            "session.list",
            "List the views currently open, with the worker PID holding each one.",
            Arc::new(object_schema(&[], &[])),
        )
        .with_title("List open views")
        .with_output_schema::<responses::ViewList>()
        .with_annotations(annotations("List open views", true, false)),
        Tool::new(
            "session.close",
            "Close a view and terminate the worker holding it. This is the only way memory \
             is returned: Binary Ninja cannot be re-initialized in a process, so the process \
             is what gets released.",
            Arc::new(object_schema(
                &[(
                    VIEW_PARAM,
                    json!({
                        "type": "string",
                        "description": "The handle from session.open.",
                    }),
                )],
                &[VIEW_PARAM],
            )),
        )
        .with_title("Close a view")
        .with_output_schema::<responses::CloseResult>()
        .with_annotations(annotations("Close a view", false, true)),
        Tool::new(
            "health.ping",
            "Connectivity check; does not open a binary or initialize Binary Ninja.",
            Arc::new(object_schema(&[], &[])),
        )
        .with_title("Ping")
        .with_output_schema::<responses::Health>()
        .with_annotations(annotations("Ping", true, false)),
    ]
}

fn object_schema(props: &[(&str, Value)], required: &[&str]) -> Map<String, Value> {
    let mut properties = Map::new();
    for (name, schema) in props {
        properties.insert((*name).to_owned(), schema.clone());
    }
    let mut schema = Map::new();
    schema.insert("type".to_owned(), json!("object"));
    schema.insert("properties".to_owned(), Value::Object(properties));
    schema.insert(
        "required".to_owned(),
        Value::Array(required.iter().map(|r| json!(r)).collect()),
    );
    schema
}

impl ServerHandler for Supervisor {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                // Without this rmcp answers all three `tasks/*` verbs with
                // `-32601` before they reach the forwards below, and the
                // `background` parameter would advertise something unreachable.
                .enable_tasks()
                .build(),
        )
        .with_server_info(vibrev_kit::engine_identity!())
        .with_instructions(
            "Binary Ninja, one worker process per open binary. Call session.open first \
             and pass the returned `view` to every analysis tool — there is no current \
             binary, on purpose. Opening runs analysis to completion, so it is slow once \
             and fast afterwards; pass `background: true` to get a task handle instead \
             of waiting.",
        )
    }

    // `vibrev_kit::tasks::TaskHost`'s, which this server implements by naming
    // its registry and its owner rule. None of the three is really async — the
    // whole face is a lookup under one mutex — so these are `async fn` only
    // because `ServerHandler` asks for it.
    async fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, ErrorData> {
        self.serve_get_task(request, &context.meta)
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.serve_update_task(request, &context.meta)
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.serve_cancel_task(request, &context.meta)
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        supervisor_tools().into_iter().find(|t| t.name == name)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(supervisor_tools()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.to_string();
        let mut args = request.arguments.unwrap_or_default();

        // Removed for every tool, because it is this supervisor's parameter and
        // a worker handed a property its schema does not declare rejects the
        // whole call. Read strictly: `"true"` and `1` are refused rather than
        // read as false, which would answer synchronously a caller who asked for
        // a handle and say nothing about why.
        let background = match args.remove(BACKGROUND_PARAM) {
            None => false,
            Some(Value::Bool(asked)) => asked,
            Some(other) => {
                return Ok(ToolError::InvalidParams(format!(
                    "`{BACKGROUND_PARAM}` is a boolean; received {other}"
                ))
                .to_response())
            }
        };
        // One check for the whole surface, and it has to stay ahead of the
        // routing split below: a check placed inside a branch cannot see the
        // tools that never take that branch, so those would accept `background`
        // and quietly ignore it — the exact thing `cannot_hold_a_handle`
        // refuses to do.
        if background && !BACKGROUNDABLE.contains(&name.as_str()) {
            return Ok(ToolError::InvalidParams(format!(
                "{name} takes no `{BACKGROUND_PARAM}`. Only {} answer with a task handle; \
                 everything else here returns in milliseconds once the view is open.",
                BACKGROUNDABLE.join(" and ")
            ))
            .to_response());
        }
        // Read once and used for both halves of the remaining decision: whether
        // to start background work, and whether to promote its carrier into a
        // protocol handle. One `bool` cannot disagree with itself, and that is
        // what keeps the carrier — which is not an answer — from reaching a
        // client.
        let can_hold =
            peer_can_hold_task_handle(context.protocol_version(), context.client_capabilities());

        // The session primitives are the supervisor's own; everything else is a
        // worker tool. Routing off the same constant the advertised list is
        // checked against means a fourth session tool cannot be advertised and
        // then fall through to a worker that has never heard of it.
        if SESSION_TOOLS.contains(&name.as_str()) {
            return match name.as_str() {
                "session.open" => {
                    let Some(path) = args.get("path").and_then(Value::as_str) else {
                        return Ok(ToolError::InvalidParams(
                            "session.open needs a `path`".to_owned(),
                        )
                        .to_response());
                    };
                    if background {
                        if !can_hold {
                            return Ok(tasks::cannot_hold_a_handle(&name).to_response());
                        }
                        let owner = self.task_owner(&context.meta);
                        let carrier = tasks::handle_or_refusal(self.spawn_open_task(&owner, path));
                        return self.materialize_task_response(true, carrier.into());
                    }
                    match self.open(path).await {
                        Ok(result) => structured(&result),
                        Err(e) => Ok(e.to_response()),
                    }
                }
                "session.list" => structured(&self.list().await),
                "session.close" => {
                    let Some(id) = args.get(VIEW_PARAM).and_then(Value::as_str) else {
                        return Ok(ToolError::InvalidParams(format!(
                            "session.close needs a `{VIEW_PARAM}`"
                        ))
                        .to_response());
                    };
                    match self.close(id).await {
                        Ok(result) => structured(&result),
                        Err(e) => Ok(e.to_response()),
                    }
                }
                "health.ping" => structured(&self.health().await),
                // Unreachable while `SESSION_TOOLS` and this match agree, and a
                // test holds them together. Answering rather than panicking
                // because a supervisor that dies takes every open view with it.
                other => Ok(ToolError::NotFound(format!(
                    "{other} is listed as a session tool but has no handler"
                ))
                .to_response()),
            };
        }

        // Everything else is a worker tool. Pull the routing key back out: the
        // worker's schema has no `view`, and passing an unknown property would
        // fail its argument validation.
        let Some(view_id) = args.remove(VIEW_PARAM).and_then(|v| match v {
            Value::String(s) => Some(s),
            _ => None,
        }) else {
            return Ok(ToolError::InvalidParams(format!(
                "{name} needs `{VIEW_PARAM}`: the handle session.open returned. This server \
                 holds several binaries at once and has no current one."
            ))
            .to_response());
        };

        if background {
            if !can_hold {
                return Ok(tasks::cannot_hold_a_handle(&name).to_response());
            }
            let owner = self.task_owner(&context.meta);
            let carrier = tasks::handle_or_refusal(self.spawn_script_task(&owner, &view_id, args));
            return self.materialize_task_response(true, carrier.into());
        }

        match self.forward(&view_id, &name, args).await {
            // Verbatim. `content`, `structuredContent` and `isError` are the
            // worker's — see the module docs for why that matters.
            Ok(result) => Ok(result.into()),
            Err(e) => Ok(e.to_response()),
        }
    }
}

/// Build a supervisor-native result the same way [`crate::server`] does, so the
/// session tools read like the analysis tools rather than like a second product.
fn structured<T: serde::Serialize + schemars::JsonSchema + 'static>(
    value: &T,
) -> Result<CallToolResponse, ErrorData> {
    structured_result(value).map(Into::into)
}

/// The same thing one step earlier, for the caller that needs the `CallToolResult`
/// itself: a settled background task stores the result, not the response.
fn structured_result<T: serde::Serialize + schemars::JsonSchema + 'static>(
    value: &T,
) -> Result<CallToolResult, ErrorData> {
    let json =
        serde_json::to_value(value).map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
    let text = vibrev_kit::render::render(&json);
    let mut result = CallToolResult::structured(json);
    result.content = vec![ContentBlock::text(text)];
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_worker_tool_gains_a_required_view_parameter() {
        let worker: Vec<String> = BnMcpServer::vibrev_tool_defs()
            .iter()
            .map(|d| d.name().to_owned())
            .collect();
        let tools = supervisor_tools();
        for name in &worker {
            let tool = tools
                .iter()
                .find(|t| t.name == name.as_str())
                .unwrap_or_else(|| panic!("{name} is missing from the supervisor surface"));
            let props = tool
                .input_schema
                .get("properties")
                .and_then(|p| p.as_object());
            assert!(
                props.is_some_and(|p| p.contains_key(VIEW_PARAM)),
                "{name} has no `{VIEW_PARAM}` property"
            );
            let required = tool
                .input_schema
                .get("required")
                .and_then(|r| r.as_array())
                .cloned()
                .unwrap_or_default();
            assert!(
                required.iter().any(|v| v == VIEW_PARAM),
                "{name} does not require `{VIEW_PARAM}`; there is no implicit current view"
            );
        }
    }

    /// `background` is advertised by exactly the two tools that act on it.
    ///
    /// Both halves matter. A tool that publishes the property and is then
    /// forwarded synchronously would be the quiet kind of wrong — the caller is
    /// told they can have a handle and gets an answer instead. And a tool that
    /// acts on it without publishing it is a capability discoverable only by
    /// reading this file.
    #[test]
    fn exactly_two_tools_offer_to_run_in_the_background() {
        let offering: Vec<String> = supervisor_tools()
            .iter()
            .filter(|tool| {
                tool.input_schema
                    .get("properties")
                    .and_then(|p| p.as_object())
                    .is_some_and(|p| p.contains_key(BACKGROUND_PARAM))
            })
            .map(|tool| tool.name.to_string())
            .collect();
        assert_eq!(offering, BACKGROUNDABLE);
    }

    /// And never required: every caller that does not know about tasks has to
    /// keep working, on both faces, without editing a single argument.
    #[test]
    fn asking_for_a_handle_is_always_optional() {
        for tool in supervisor_tools() {
            let required = tool
                .input_schema
                .get("required")
                .and_then(|r| r.as_array())
                .cloned()
                .unwrap_or_default();
            assert!(
                !required.iter().any(|v| v == BACKGROUND_PARAM),
                "{} requires `{BACKGROUND_PARAM}`",
                tool.name
            );
        }
    }

    /// The worker publishes no `background` and is never sent one.
    ///
    /// It is the supervisor's parameter — the worker runs the script exactly the
    /// way it always has, and this process is what stops waiting. A worker handed
    /// a property its schema does not declare rejects the whole call, so this is
    /// the same rule `view` lives under.
    #[test]
    fn the_worker_surface_has_no_background_parameter() {
        for def in BnMcpServer::vibrev_tool_defs() {
            let props = def
                .tool
                .input_schema
                .get("properties")
                .and_then(|p| p.as_object());
            assert!(
                !props.is_some_and(|p| p.contains_key(BACKGROUND_PARAM)),
                "{} declares `{BACKGROUND_PARAM}` on the worker surface",
                def.name()
            );
        }
    }

    /// The tool the background branch names has to be one the supervisor really
    /// forwards, or `background: true` would route to a worker tool that does
    /// not exist and the schema graft would silently never fire.
    #[test]
    fn the_backgroundable_worker_tool_is_a_real_worker_tool() {
        assert!(BnMcpServer::vibrev_tool_defs()
            .iter()
            .any(|d| d.name() == BACKGROUNDABLE_WORKER_TOOL));
        assert!(!SESSION_TOOLS.contains(&BACKGROUNDABLE_WORKER_TOOL));
    }

    /// The worker surface must stay free of `view`: it is one process, one view,
    /// and a property the worker does not accept would be rejected on arrival.
    #[test]
    fn the_worker_surface_has_no_view_parameter() {
        for def in BnMcpServer::vibrev_tool_defs() {
            let props = def
                .tool
                .input_schema
                .get("properties")
                .and_then(|p| p.as_object());
            assert!(
                !props.is_some_and(|p| p.contains_key(VIEW_PARAM)),
                "{} declares `{VIEW_PARAM}` on the worker surface",
                def.name()
            );
        }
    }

    /// A title, annotations and an output schema on every advertised tool —
    /// hand-written ones included. The macro enforces this for the derived
    /// tools and cannot reach these four, which is why the assertion exists.
    #[test]
    fn supervisor_tools_declare_their_metadata() {
        for tool in supervisor_tools() {
            assert!(tool.title.is_some(), "{} has no title", tool.name);
            assert!(
                tool.annotations.is_some(),
                "{} has no annotations",
                tool.name
            );
            assert!(
                tool.output_schema.is_some(),
                "{} has no outputSchema",
                tool.name
            );
        }
    }

    #[test]
    fn session_tool_names_match_the_routing_table() {
        let advertised: Vec<String> = session_tools().iter().map(|t| t.name.to_string()).collect();
        assert_eq!(advertised, SESSION_TOOLS);
    }

    #[test]
    fn health_ping_is_advertised_without_a_view() {
        let tool = session_tools()
            .into_iter()
            .find(|t| t.name == "health.ping")
            .expect("health.ping is advertised");
        let props = tool
            .input_schema
            .get("properties")
            .and_then(|p| p.as_object());
        assert!(
            !props.is_some_and(|p| p.contains_key(VIEW_PARAM)),
            "health.ping must not take `{VIEW_PARAM}`"
        );
        assert_eq!(tool.title.as_deref(), Some("Ping"));
        let annotations = tool
            .annotations
            .as_ref()
            .expect("health.ping has no annotations");
        assert_eq!(annotations.read_only_hint, Some(true));
        assert_eq!(annotations.destructive_hint, Some(false));
        assert_eq!(annotations.idempotent_hint, Some(true));
        assert_eq!(annotations.open_world_hint, Some(false));
        assert!(
            tool.output_schema.is_some(),
            "health.ping has no outputSchema"
        );
    }

    #[test]
    fn tool_order_is_deterministic() {
        // Two builds of the same binary must publish the same list in the same
        // order, or every client's cache key changes for nothing.
        let a: Vec<String> = supervisor_tools()
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        let b: Vec<String> = supervisor_tools()
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        assert_eq!(a, b);
        let mut sorted = a.clone();
        sorted.sort();
        assert_eq!(a, sorted);
    }

    #[test]
    fn idle_reap_decision_covers_every_case() {
        let cases = [
            (0, 10_000, 0, IdleReapDecision::TtlDisabled),
            (1800, 1799, 0, IdleReapDecision::NotYetIdle),
            (1800, 1800, 0, IdleReapDecision::Idle),
            (1800, 1800, 1, IdleReapDecision::InflightBusy),
        ];
        for (ttl_secs, idle_secs, inflight, want) in cases {
            let got = idle_reap_decision(
                IdleTtl::from_secs(ttl_secs),
                Duration::from_secs(idle_secs),
                inflight,
            );
            assert_eq!(
                got, want,
                "ttl={ttl_secs} idle={idle_secs} inflight={inflight}"
            );
            assert_eq!(got.should_reap(), want == IdleReapDecision::Idle);
        }
    }

    #[test]
    fn idle_ttl_default_is_thirty_minutes() {
        assert_eq!(IdleTtl::DEFAULT, IdleTtl::from_secs(1800));
        assert_eq!(IdleTtl::ENV, "BN_IDLE_TTL_SECS");
        assert!(IdleTtl::from_secs(0).disabled());
        assert!(!IdleTtl::DEFAULT.disabled());
    }
}
