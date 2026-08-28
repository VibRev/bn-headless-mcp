//! The `tasks/*` face (SEP-2663), wired to `vibrev_kit::tasks`.
//!
//! **One registry, and it lives on the supervisor.** `script.python` would sit
//! naturally on the worker, but the other backgroundable tool cannot:
//! `session.open` is not a worker tool at all — it is one of the four the
//! supervisor answers itself, and it has to be, because opening a view *is*
//! spawning the worker that would otherwise have owned the task. A registry
//! split across both faces would leave the supervisor routing `tasks/get` by
//! task id to the right child process, for a face clients only ever reach
//! through it. So the registry sits on the one face clients connect to.
//!
//! **The worker gives up nothing for this.** `script.python` still runs
//! synchronously inside its worker; the supervisor is what stops waiting. So the
//! worker stays a plain MCP server, `Capped` still catches an oversized answer
//! before it crosses the pipe, and the verbatim guarantee in the parent module's
//! docs holds — a settled task carries the worker's own `CallToolResult`,
//! serialized, not a second rendering of it.
//!
//! **This engine publishes no polling verb of its own.** MCP already defines
//! `tasks/get`, so a hand-rolled `task_status` tool would be a second protocol
//! living beside the standard one, discoverable only by reading this server's
//! tool list. A client that cannot hold a protocol handle is refused instead
//! (see [`cannot_hold_a_handle`]) and loses nothing by it: omitting `background`
//! gives that caller the same answer, synchronously.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rmcp::model::{CallToolResult, ContentBlock, RequestMetaObject};
use serde_json::{json, Map, Value};
use tracing::{info, warn};
use vibrev_kit::tasks::{
    call_tool_result_to_value, TaskCompletionDecision, TaskCreateError, TaskHost, TaskOwner,
    TaskRegistry,
};

use super::Supervisor;
use crate::error::ToolError;

/// The property both background-capable tools grow, named once.
pub(super) const BACKGROUND_PARAM: &str = "background";

/// Poll cadence advertised with every handle this engine hands out.
///
/// The kit's default is 5,000 ms and its own documentation says why that is
/// wrong here: five seconds suits work measured in minutes, and a client that
/// believes it waits five seconds to learn something that was ready in one.
/// `session.open` is a load plus one analysis pass — seconds on the binaries
/// people open. `script.python` can run for its full 600 s, but a hint tuned for
/// the slower of the two would mis-time the one callers actually wait on.
const POLL_INTERVAL_MS: u64 = 500;

/// Checked at compile time rather than in a test, because the failure it guards
/// against is someone deleting the override and inheriting the kit's default
/// back — which a test could be deleted alongside.
const _: () = assert!(POLL_INTERVAL_MS < vibrev_kit::tasks::DEFAULT_POLL_INTERVAL_MS);

/// Which face this handler answers on — the whole of the owner rule.
///
/// The rule is coarse on purpose and reads no request metadata at all: holding a
/// task handle requires protocol 2026-07-28, and on HTTP *every* request at that
/// version is dispatched statelessly. So every task this engine can create on
/// the listening face belongs to `Runtime` unconditionally, and stdio — one
/// connection-scoped handler for the life of the process — is the only place a
/// `Session` owner means anything.
///
/// Metadata cannot be the judge here, because rmcp's own rule does not depend on
/// it: `uses_legacy_lifecycle` picks the stateless route on protocol version
/// alone, and takes that version from the body metadata *or the
/// `MCP-Protocol-Version` header*, while `stateless_protocol_metadata_required`
/// defaults to `false` — so a request can be dispatched statelessly carrying an
/// incomplete `_meta`. Any test of `_meta` completeness therefore mislabels
/// exactly the requests that matter. The handler is rebuilt per POST either way,
/// so a task filed under that handler's identity is one no later request can
/// ever name again: a handle that answers `Unknown task_id` forever, with a live
/// Binary Ninja worker under it that nothing will close until the idle reaper
/// does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Face {
    Stdio,
    Http,
}

/// The identity one stdio connection's tasks are filed under.
///
/// A counter rather than a UUID, deliberately: an owner is compared inside this
/// process and never crosses the wire, so unguessability buys nothing here. Task
/// *ids* are the opposite — every HTTP caller shares the one `Runtime` owner,
/// which makes the id itself the bearer capability — and those the kit generates
/// as full UUIDv4s.
pub(super) fn new_session_owner() -> TaskOwner {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    TaskOwner::Session(Arc::from(
        format!("conn-{}", NEXT.fetch_add(1, Ordering::Relaxed)).as_str(),
    ))
}

impl TaskHost for Supervisor {
    fn task_registry(&self) -> &TaskRegistry {
        &self.tasks
    }

    fn task_owner(&self, _meta: &RequestMetaObject) -> TaskOwner {
        match self.face {
            Face::Stdio => self.session_owner.clone(),
            Face::Http => TaskOwner::Runtime,
        }
    }

    fn task_poll_interval_ms(&self) -> u64 {
        POLL_INTERVAL_MS
    }
}

impl Supervisor {
    /// Run `session.open` in the background and return the task id.
    ///
    /// **The dedup key is unique per call, and must stay that way.** Keying on
    /// the canonical path instead would only ever produce a wrong refusal on the
    /// listening face: every HTTP caller is `TaskOwner::Runtime`, and the kit
    /// discloses a running task's id only to a matching `Session` owner, so the
    /// second caller to ask for a path would be told the work belongs to
    /// *another caller* — which is not true, since they share the one owner. The
    /// saving such a key looks like it buys is already made one layer down:
    /// `open` canonicalizes under `open_lock` and hands the second caller the
    /// existing view. A second handle that settles with `reused: true` is both
    /// true and more use.
    pub(super) fn spawn_open_task(
        &self,
        owner: &TaskOwner,
        path: &str,
    ) -> Result<String, TaskCreateError> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let key = format!("session.open:{}", NEXT.fetch_add(1, Ordering::Relaxed));
        let task_id = self.tasks.create_keyed(
            owner,
            "open",
            &key,
            "Loading, and running Binary Ninja's analysis to convergence",
        )?;

        let supervisor = self.clone();
        let registry = self.tasks.clone();
        let token = self.lifetime.child_token();
        let observed = token.clone();
        let path = path.to_owned();
        let tid = task_id.clone();
        // Registered before the spawn, not after. The kit does handle a token
        // that arrives late — but only for the task's *status*: a cancel landing
        // in the gap sets `cancel_requested` without signalling the token, and
        // the settle then reports the kit's generic wording instead of this
        // engine's, which is the one place the wording is load-bearing.
        self.tasks.set_cancel_token(&task_id, token);
        tokio::spawn(async move {
            // Binary Ninja loads one at a time (`open_lock`), so a queued task
            // saying it is "loading" is saying something false. `try_lock` can
            // be stale by the time `open` asks for the lock properly, which is
            // why this sets a message and never a decision.
            if supervisor.open_lock.try_lock().is_err() {
                registry.update_message(
                    &tid,
                    "Waiting for another session.open to finish; this engine loads one \
                     binary at a time",
                );
            }
            let outcome = supervisor.open(&path).await;
            // A view *this* task created is a resource cancellation has to take
            // back. A reused one is not: the caller who opened it first is still
            // using it, and closing it would kill their worker.
            let created = match &outcome {
                Ok(open) if !open.reused => Some(open.view.clone()),
                _ => None,
            };
            let result = match &outcome {
                Ok(open) => super::structured_result(open),
                Err(e) => Ok(e.to_tool_result()),
            };
            let value = match result {
                Ok(result) => call_tool_result_to_value(&result),
                Err(e) => {
                    // Unreachable in practice — `OpenResult` is strings, a bool
                    // and an `Option<u32>` — but a failure here would otherwise
                    // leave a live worker the caller has no handle for, so it
                    // says which one and how to find it.
                    registry.fail(
                        &tid,
                        &format!(
                            "the view opened{}, but its answer could not be serialized: {e}. \
                             session.list will show it; session.close takes it back.",
                            created
                                .as_deref()
                                .map(|v| format!(" as {v}"))
                                .unwrap_or_default()
                        ),
                    );
                    return;
                }
            };

            // Deferred rather than `complete_with_cancel_token`, because there is
            // something to clean up: settling straight to `Cancelled` would
            // discard the result and leave the worker running with nobody
            // holding its handle.
            match registry.complete_or_defer_cancellation(&tid, value, &observed) {
                TaskCompletionDecision::Completed | TaskCompletionDecision::Unchanged => {}
                TaskCompletionDecision::CancellationPending => match created {
                    Some(view) if supervisor.untouched_since_open(&view).await => {
                        match supervisor.close(&view).await {
                            Ok(_) => {
                                info!(task = %tid, view = %view, "cancelled open; closed the view it created");
                                registry.finish_cancelled(
                                    &tid,
                                    &format!(
                                        "Cancelled; the view this open created ({view}) was closed"
                                    ),
                                );
                            }
                            Err(e) => {
                                warn!(task = %tid, view = %view, error = %e, "cancelled open; closing failed");
                                registry.fail_after_cleanup_error(
                                    &tid,
                                    &format!(
                                        "Cancelled, but closing {view} failed: {e}. The worker \
                                         may still be running — session.list will show it."
                                    ),
                                );
                            }
                        }
                    }
                    // Created, but somebody has used it since. `open` releases
                    // `open_lock` before it returns, so between that return and
                    // this cleanup a synchronous `session.open` of the same path
                    // can have been handed this very view — and closing it then
                    // kills a worker that is in use. The idle reaper guards the
                    // same race with the same re-read; this is the other half.
                    Some(view) => {
                        info!(task = %tid, view = %view, "cancelled open; view is in use, left open");
                        registry.finish_cancelled(
                            &tid,
                            &format!(
                                "Cancelled; {view} was opened but another caller is already \
                                 using it, so it was left open. session.close takes it back."
                            ),
                        );
                    }
                    None => {
                        registry.finish_cancelled(
                            &tid,
                            "Cancelled; that path was already open, so the existing view was \
                             left alone",
                        );
                    }
                },
            }
        });
        Ok(task_id)
    }

    /// Forward `script.python` in the background and return the task id.
    ///
    /// Not deduplicated, for the same reason [`Self::spawn_open_task`] is not:
    /// two scripts are not one operation, they already serialize inside the
    /// worker on `Engine::write`, and refusing the second would be a narrower
    /// promise than the synchronous path keeps.
    pub(super) fn spawn_script_task(
        &self,
        owner: &TaskOwner,
        view_id: &str,
        args: Map<String, Value>,
    ) -> Result<String, TaskCreateError> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let key = format!(
            "script.python:{view_id}:{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let task_id = self.tasks.create_keyed(
            owner,
            "script",
            &key,
            "Submitted to the worker holding this view",
        )?;

        let supervisor = self.clone();
        let registry = self.tasks.clone();
        let token = self.lifetime.child_token();
        let observed = token.clone();
        let view_id = view_id.to_owned();
        let tid = task_id.clone();
        // Before the spawn — see `spawn_open_task` for why the gap matters.
        self.tasks.set_cancel_token(&task_id, token);
        tokio::spawn(async move {
            let result = supervisor.forward(&view_id, "script.python", args).await;
            // Verbatim on this path too: a settled task carries the bytes the
            // worker produced, and a worker that reported `isError` still
            // *completed* — the distinction between "the script raised" and "the
            // worker died" is one a caller has to be able to make.
            let value = match result {
                Ok(result) => call_tool_result_to_value(&result),
                Err(e) => call_tool_result_to_value(&e.to_tool_result()),
            };
            registry.complete_with_cancel_token(&tid, value, &observed, CANCELLED_SCRIPT);
        });
        Ok(task_id)
    }
}

/// What cancelling a running script actually did, said plainly.
///
/// Nothing interrupts it. The script was handed to the worker's Python console
/// before the cancel arrived, and `script.python` already documents that even
/// its own `timeout_secs` cannot break a call parked inside Binary Ninja's core.
/// So the task stays `Running` — the kit keeps it there, with "waiting for the
/// operation to settle" on it — until the worker answers, and only then does it
/// settle as cancelled. A message claiming the script was stopped would be the
/// one thing worse than not offering cancel at all.
///
/// The second sentence is the other half of the same honesty. A cancelled task
/// keeps no result, and `script.python` runs arbitrary Python — it may have
/// renamed, patched, or written a database on its way through. Cancelling
/// discards the *answer*, not the work.
const CANCELLED_SCRIPT: &str =
    "Cancelled after the script settled. Cancelling never interrupted it: it had already \
     been submitted, and ran to completion or to its own timeout_secs. Its output was \
     discarded — anything it changed in the view is still changed.";

/// Turn "background work started, or would not start" into the carrier
/// [`TaskHost::materialize_task_response`] promotes into a protocol handle.
pub(super) fn handle_or_refusal(outcome: Result<String, TaskCreateError>) -> CallToolResult {
    match outcome {
        Ok(task_id) => carrier(
            &task_id,
            "Started. Poll it with tasks/get; cancel it with tasks/cancel.",
        ),
        // Both dedup outcomes are unreachable: every key this engine builds is
        // unique per call, deliberately (see `spawn_open_task`). They are still
        // answered rather than `unreachable!()`, because a supervisor that
        // panics takes every open view down with it — the same reason the
        // unknown-session-tool arm in `call_tool` answers instead of panicking.
        Err(TaskCreateError::AlreadyRunning(existing)) => carrier(
            &existing,
            "That work was already running; this call joined it.",
        ),
        Err(TaskCreateError::ExistingTaskIdIsPrivate) => ToolError::Busy(
            "the same work is already running and its handle is not this caller's to \
             poll. Retry, or call this without `background`."
                .to_owned(),
        )
        .to_tool_result(),
        // Nothing failed and nothing the caller wrote is wrong; there is simply
        // no room right now. `Worker` would blame a process that is fine.
        Err(TaskCreateError::CapacityExceeded { max_entries }) => ToolError::Busy(format!(
            "the background task registry is full: all {max_entries} slots hold running \
             work. Let something finish, or cancel one with tasks/cancel."
        ))
        .to_tool_result(),
    }
}

/// The value a backgrounded tool hands back *before* promotion.
///
/// It never reaches a client. This engine starts background work only when the
/// peer can hold a protocol handle, and the single `bool` that decides that is
/// the one handed to `materialize_task_response` — they cannot disagree, because
/// there is only one of them. The text is compact JSON rather than this engine's
/// rendered form because the kit reads the task id back out of
/// `content[0].text`: this is the kit's carrier, not an answer.
fn carrier(task_id: &str, message: &str) -> CallToolResult {
    let payload = json!({ "status": "started", "task_id": task_id, "message": message });
    let mut result = CallToolResult::structured(payload.clone());
    result.content = vec![ContentBlock::text(payload.to_string())];
    result
}

/// Why `background: true` from a peer that cannot hold a handle is refused
/// rather than served.
///
/// Both alternatives are worse. Handing back the started-payload leaves the
/// caller a task id and no verb able to poll it, because this engine ships no
/// `task_status` tool. Quietly answering synchronously would be ignoring a
/// parameter the caller typed — and the caller who drops `background` gets that
/// same synchronous answer, having chosen it.
pub(super) fn cannot_hold_a_handle(tool: &str) -> ToolError {
    ToolError::InvalidParams(format!(
        "{tool} cannot run in the background for this client: a task handle needs MCP \
         protocol 2026-07-28 and the `tasks` capability, and this connection negotiated \
         neither. Call it without `{BACKGROUND_PARAM}` and the answer comes back the way \
         it always has."
    ))
}

/// The `background` property, described once per tool but refused the same way.
pub(super) fn background_property(what_it_defers: &str) -> Value {
    json!({
        "type": "boolean",
        "description": format!(
            "Return an MCP task handle immediately instead of waiting. {what_it_defers} \
             Needs a client that negotiated protocol 2026-07-28 and the `tasks` \
             capability; without one the call is refused rather than answered with a \
             handle nothing can poll."
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{ClientCapabilities, ProtocolVersion};
    use vibrev_kit::tasks::task_id_from_call_tool_result;

    /// The carrier has exactly one job, and it is a JSON contract:
    /// `materialize_task_response` reads the task id back out of
    /// `content[0].text`. Rendering it the way every other answer here is
    /// rendered would break that silently — the kit would find no id, pass the
    /// carrier through unchanged, and a client would receive an internal
    /// bookkeeping object as if it were the answer to its call.
    #[test]
    fn the_kit_can_read_the_task_id_back_out_of_the_carrier() {
        let result = carrier("open-abc123", "Started.");
        assert_eq!(
            task_id_from_call_tool_result(&result).as_deref(),
            Some("open-abc123")
        );
    }

    /// The two refusals that have no id must not look like handles. The kit
    /// passes an id-less result straight through, which is what makes them
    /// arrive as ordinary `isError` answers rather than as broken handles.
    #[test]
    fn a_refusal_carries_no_handle_and_reports_failure() {
        for outcome in [
            Err(TaskCreateError::ExistingTaskIdIsPrivate),
            Err(TaskCreateError::CapacityExceeded { max_entries: 256 }),
        ] {
            let result = handle_or_refusal(outcome);
            assert_eq!(result.is_error, Some(true));
            assert!(task_id_from_call_tool_result(&result).is_none());
        }
    }

    /// A task already running for *this* owner is not a refusal: its id is the
    /// handle the caller was asking for, so it comes back as a handle rather
    /// than as an error.
    #[test]
    fn joining_a_running_task_hands_back_its_id() {
        let result = handle_or_refusal(Err(TaskCreateError::AlreadyRunning("open-x".to_owned())));
        assert_ne!(result.is_error, Some(true));
        assert_eq!(
            task_id_from_call_tool_result(&result).as_deref(),
            Some("open-x")
        );
    }

    /// Cancelling a script does not stop it, and the message a client reads has
    /// to say so. This is the one place the wording is load-bearing.
    #[test]
    fn the_script_cancellation_message_does_not_claim_the_script_was_stopped() {
        assert!(CANCELLED_SCRIPT.contains("never interrupted it"));
        assert!(CANCELLED_SCRIPT.contains("timeout_secs"));
    }

    /// Two connections must not share an identity, or one HTTP client could poll
    /// and cancel another's work.
    #[test]
    fn two_connections_do_not_share_a_task_owner() {
        assert_ne!(new_session_owner(), new_session_owner());
    }

    fn complete_meta() -> RequestMetaObject {
        let mut meta = RequestMetaObject::new();
        meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
        meta.set_client_capabilities(ClientCapabilities::builder().enable_tasks().build());
        assert!(
            meta.missing_required_keys(&ProtocolVersion::V_2026_07_28)
                .is_empty(),
            "the fixture is meant to be the complete key set"
        );
        meta
    }

    /// The owner rule reads the face and nothing else — this is the assertion
    /// that a rewrite of it has to survive.
    ///
    /// Both metadata shapes are checked precisely because neither may change the
    /// answer. An owner rule that consulted `_meta` would file some stateless
    /// HTTP requests under a per-POST handler identity that dies with the
    /// response, and the handle would answer `Unknown task_id` forever over a
    /// live Binary Ninja worker; rmcp decides statelessness on protocol version
    /// alone, and reads that version from the header when the body omits it, so
    /// an incomplete `_meta` says nothing about how a request was dispatched.
    #[tokio::test]
    async fn the_owner_follows_the_face_and_never_the_request_metadata() {
        let stdio = Supervisor::new().expect("a supervisor");
        let http = stdio.http_face();

        for meta in [complete_meta(), RequestMetaObject::new()] {
            assert_eq!(
                stdio.task_owner(&meta),
                stdio.session_owner,
                "stdio has one connection-scoped handler however modern the client is"
            );
            assert_eq!(
                http.task_owner(&meta),
                TaskOwner::Runtime,
                "every task-capable HTTP request is dispatched statelessly"
            );
        }
    }

    /// The listening face shares one registry with the process — a second
    /// registry would make `tasks/get` answer "unknown task" for a handle this
    /// process had just issued.
    #[tokio::test]
    async fn every_http_connection_reads_one_registry() {
        let base = Supervisor::new().expect("a supervisor");
        let one = base.http_face();
        let two = base.http_face();

        let owner = TaskOwner::Runtime;
        let id = one
            .tasks
            .create_keyed(&owner, "open", "/bin/cat", "Loading")
            .expect("a task");
        assert!(
            two.task_registry().get_for_owner(&owner, &id).is_some(),
            "a second connection cannot see the first connection's task"
        );
        assert!(base.task_registry().get(&id).is_some());
    }
}
