//! The only place this engine calls the Binary Ninja API.
//!
//! That is a hard rule rather than a preference: the Rust API has no crates.io
//! release and no stable branch, and pinning one commit only makes the breakage
//! *scheduled* rather than absent. Funnelling every `bn` call through one module
//! means a version bump is a diff against this file, not a diff against the whole
//! engine. See the README section "Version pinning".
//!
//! Three upstream constraints are encoded here, all of them measured rather than
//! assumed:
//!
//! * **#6660 — a Session cannot be re-initialized.** Dropping the last `Session`
//!   calls `BNShutdown`, and the next `Session::new()` hangs (300 s, no return —
//!   the issue reports a segfault, this machine reproduces a hang, which is worse
//!   because it leaves no core dump). [`Engine`] therefore initializes once per
//!   process and never *re*-initializes; a closed session is a dead process, and
//!   the OS is what reclaims the memory. Shutdown does eventually run, at
//!   process exit — which is why [`Engine`]'s field order is load bearing, see
//!   the note on the type.
//! * **Analysis convergence changes answers.** The same function rendered 1876
//!   and then 1836 characters of Pseudo C to one thread while analysis was still
//!   converging. Everything here settles analysis before it reads.
//! * **Concurrency is safe but caps out at 3–4×.** A shared `BinaryView`
//!   hammered from 8 threads for 20 s: no crash, no deadlock, and 8,652
//!   cross-thread observations of the same function agreed exactly. Distinct
//!   `BinaryView`s are equally safe in parallel, so no worker-wide lock is needed
//!   and [`MAX_INFLIGHT`] per view is the whole bound. Speedup was 3.83× on a
//!   16-core machine, so [`MAX_INFLIGHT`] is 4 and more would only add CPU
//!   contention — which is itself what makes analysis converge slower.

use std::path::Path;
use std::sync::Arc;

use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::headless::{InitializationOptions, Session};
use binaryninja::rc::Ref;
use binaryninjacore_sys::BNAnalysisState;
use tokio::sync::Semaphore;

use crate::error::ToolError;

pub mod disasm;
pub mod patch;
pub mod pseudo_c;
pub mod read;
pub mod script;

/// Concurrent Binary Ninja calls allowed per view. See the module docs — this is
/// a measured ceiling, not a guess.
pub const MAX_INFLIGHT: usize = 4;

/// The Binary Ninja API commit this build compiles against.
///
/// Duplicated from `Cargo.toml` on purpose: `doctor` has to be able to print it,
/// and there is no build-time way to read a git dependency's `rev` back out. The
/// test at the bottom of this module reads the manifest and fails if the two ever
/// disagree — the one thing worse than a version number is a wrong one.
pub const PINNED_API_REVISION: &str = "aa25bfcfd36532ec3850558a58444df7727e297b";

/// One process's worth of Binary Ninja: one `Session`, one `BinaryView`.
///
/// One view per process is deliberate even though a single `Session` can hold
/// several at once. Closing a view has to give the memory back, and #6660 rules
/// out the only in-process way to do that; process exit is the only mechanism
/// that actually works. The supervisor pays for this with one BN initialization
/// (~1.6 s) per open binary.
///
/// **Field order is load bearing.** Rust drops fields in declaration order, and
/// dropping the last `Session` calls `BNShutdown` (`headless.rs`'s
/// `impl Drop for Session` → `shutdown()`). Anything that hands a pointer back to
/// the core has to be gone before that happens, so `_session` is declared
/// **last** and everything that outlives it in the source outlives it at runtime
/// too.
///
/// Nothing may assume the session simply outlives the process: `main.rs` drops
/// the engine inside `block_on` and only then calls `process::exit`, so the drop
/// really does run. A `_session` declared any earlier than last frees the
/// `BinaryView` — and, once a script has run, tears down a Python interpreter —
/// against a core that has already shut down, on every clean exit.
pub struct Engine {
    /// The Python console, started on first use.
    ///
    /// `None` until a script tool is called, because starting it costs a Python
    /// interpreter initialization that a worker doing only reads should not pay.
    /// The `Mutex` is what makes [`script::Console`]'s `unsafe impl Send` sound:
    /// there is one console and only one thread may be inside it.
    console: std::sync::Mutex<Option<script::Console>>,
    view: Ref<BinaryView>,
    input_path: String,
    inflight: Semaphore,
    /// Serializes every tool that changes the view.
    ///
    /// [`read`](Self::read) allows [`MAX_INFLIGHT`] calls at once, which is
    /// measured safe *for reads*. A patch is not a read: it is
    /// decode-length → assemble → snapshot → write → re-analyze → snapshot, and
    /// two of those interleaved report each other's bytes and size a NOP-fill
    /// against an instruction that is no longer there. The undo bracket a patch
    /// opens is per-`FileMetadata`, so two of those interleaved would nest into
    /// one entry as well.
    writes: tokio::sync::Mutex<()>,
    /// Held for the process lifetime. Declared last so it is dropped last — see
    /// the type-level comment, this is not cosmetic.
    _session: Session,
}

impl Engine {
    /// Initialize Binary Ninja and load `path`, returning only once analysis has
    /// settled.
    ///
    /// `update_analysis_and_wait = true` on the load does two jobs: it sidesteps
    /// #8165 (analysis wedging when driven incrementally), and it means the first
    /// answer this process gives is already the converged one.
    pub fn open(path: &str) -> Result<Self, ToolError> {
        if !Path::new(path).exists() {
            return Err(ToolError::InvalidParams(format!(
                "no such file: {path} (bn-headless-mcp opens a binary or a .bndb by path)"
            )));
        }

        // `Session::new()` refuses when it cannot locate a license, but its error
        // does not say where it looked. Say it here instead: a missing BN_LICENSE
        // is the single most common way this engine fails to start, and headless
        // needs Commercial or Ultimate.
        let session = Session::new_with_opts(InitializationOptions::default()).map_err(|e| {
            ToolError::Bn(format!(
                "Binary Ninja initialization failed: {e}. Headless operation needs a \
                 Commercial or Ultimate license; set BN_LICENSE to the license text, or \
                 put license.dat in the Binary Ninja user directory."
            ))
        })?;

        // ⚠ `options` must be `Some`, never `None`. In this pinned revision the
        // `None` branch of `load_with_options_and_progress` builds its default
        // through `Metadata::new_of_type(KeyValueDataType).get_json_string()`,
        // and that method answers `None` for every type except
        // `StringDataType` (`src/metadata.rs:170`). The `.ok()?` therefore
        // returns before the core is ever called: `load_with_options(p, true,
        // None)` fails for *every* input. [Measured] `/bin/cat` — `load()` ok,
        // `None` fails, `Some("{}")` ok.
        //
        // `update_analysis_and_wait = true` is spelled out here rather than
        // taken from `Session::load`'s hardcoded default because it is load
        // bearing twice over: it sidesteps #8165, and it is what makes the first
        // answer this process gives the converged one.
        const DEFAULT_LOAD_OPTIONS: &str = "{}";
        let view = session
            .load_with_options(path, true, Some(DEFAULT_LOAD_OPTIONS.to_string()))
            .ok_or_else(|| {
                ToolError::Bn(format!(
                    "Binary Ninja could not load {path} (unrecognized format, or no view \
                     type claimed it)"
                ))
            })?;

        Ok(Self {
            console: std::sync::Mutex::new(None),
            view,
            input_path: path.to_owned(),
            inflight: Semaphore::new(MAX_INFLIGHT),
            writes: tokio::sync::Mutex::new(()),
            _session: session,
        })
    }

    pub fn input_path(&self) -> &str {
        &self.input_path
    }

    /// Run `f` against the view, on a blocking thread, with at most
    /// [`MAX_INFLIGHT`] such calls outstanding.
    ///
    /// Binary Ninja calls are synchronous and some of them are slow — rendering
    /// 177 functions cold was measured at 4.1 s — so they must not run on a
    /// runtime worker. The permit is held across the whole call, which is what
    /// makes the bound real rather than decorative.
    ///
    /// Analysis is settled *before* `f` runs, not after: an answer read from an
    /// unsettled view is wrong in a way the caller cannot detect.
    ///
    /// Every read settles, not only the load in [`open`](Self::open). Readiness
    /// is not a session-level property: under CPU starvation the Pseudo C
    /// non-determinism comes back on a view that had fully converged when it was
    /// opened, so waiting once is not enough.
    pub async fn read<T, F>(self: &Arc<Self>, f: F) -> Result<T, ToolError>
    where
        F: FnOnce(&BinaryView) -> T + Send + 'static,
        T: Send + 'static,
    {
        let _permit = self
            .inflight
            .acquire()
            .await
            .map_err(|_| ToolError::Bn("engine is shutting down".to_owned()))?;
        let me = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            me.view.update_analysis_and_wait();
            f(me.view.as_ref())
        })
        .await
        .map_err(|e| ToolError::Bn(format!("Binary Ninja call panicked or was cancelled: {e}")))
    }

    /// Run `f` against the view with every other writer excluded.
    ///
    /// Same settle-first rule as [`read`](Self::read), plus the [`writes`]
    /// mutex: a tool that changes the view must be the only one doing so. Reads
    /// still run alongside it — concurrent reads of one view agree, and a reader
    /// that catches a half-applied patch is a reader that would have caught it a
    /// millisecond later anyway.
    ///
    /// Every tool annotated `read_only = false` goes through this. That rule is
    /// worth more than picking the ones that look risky: `patch.assemble` is the
    /// one that provably breaks, but the others differ only in degree.
    ///
    /// [`writes`]: Self#structfield.writes
    pub async fn write<T, F>(self: &Arc<Self>, f: F) -> Result<T, ToolError>
    where
        F: FnOnce(&BinaryView) -> T + Send + 'static,
        T: Send + 'static,
    {
        let _writes = self.writes.lock().await;
        self.read(f).await
    }

    /// Run `f` with the view *and* this process's Python console, starting the
    /// console if this is the first script.
    ///
    /// Shares [`read`]'s permit and its settle-before-you-look rule: a script
    /// that counts functions is as wrong on an unconverged view as a list tool
    /// is. Unlike `read`, the console is serialized against itself — there is one
    /// interpreter, and two scripts in it at once would interleave their output
    /// into one another's sentinels.
    pub async fn script<T, F>(self: &Arc<Self>, f: F) -> Result<T, ToolError>
    where
        F: FnOnce(&BinaryView, &mut script::Console) -> T + Send + 'static,
        T: Send + 'static,
    {
        // A script can do anything a write tool can, so it takes the write lock
        // too. The cost is that a long script blocks writes for its whole run;
        // the alternative is a script patching bytes while `patch.assemble` is
        // sizing a NOP-fill against them, which is the hazard `writes` exists
        // for. Reads are unaffected.
        let _writes = self.writes.lock().await;
        let _permit = self
            .inflight
            .acquire()
            .await
            .map_err(|_| ToolError::Bn("engine is shutting down".to_owned()))?;
        let me = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            me.view.update_analysis_and_wait();
            let mut guard = me
                .console
                .lock()
                .map_err(|_| ToolError::Bn("the Python console is poisoned".to_owned()))?;
            if guard.is_none() {
                *guard = Some(script::Console::new(me.view.as_ref())?);
            }
            let console = guard
                .as_mut()
                .expect("the console was just created if it was absent");
            Ok(f(me.view.as_ref(), console))
        })
        .await
        .map_err(|e| ToolError::Bn(format!("the Python console panicked or was cancelled: {e}")))?
    }
}

// Field names and semantics here are kept aligned with `ida-headless-mcp`'s
// coverage type: a client should not have to learn two shapes to ask "is this
// number final?". The two engines answer the question differently, and
// `engine_state` is the one field allowed to diverge. This constraint binds this
// repository rather than the caller, so it stays a plain comment — promoting it
// into the doc comment would publish another engine's name in the JSON Schema
// every tool sends over `tools/list`.

/// How complete the analysis behind an answer was, sampled *before* the answer
/// was read.
///
/// **Sampling order.** Completeness only moves forward, so reading it before the
/// data means a `complete: true` was still true when the data was read. The
/// reverse order would stamp "complete" on an answer that was half-read while
/// analysis was still catching up.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AnalysisCoverage {
    /// True when analysis had settled before this answer was read.
    ///
    /// False means every count and list is a floor, not a total. Exactly
    /// `state == Complete`; the cheapest check a client can write is also the
    /// correct one.
    pub complete: bool,
    /// The same answer, with "could not tell" spelled out separately.
    pub state: AnalysisCoverageState,
    /// True while Binary Ninja was still analyzing when this answer was read.
    ///
    /// Separates "wait and re-read" from "analysis stopped early and will not
    /// resume by itself" — the latter is `false` alongside `complete: false`.
    pub analysis_running: bool,
    /// Binary Ninja's own `BNAnalysisState`, for diagnostics only.
    ///
    /// `IdleState`, `AnalyzeState`, `HoldState`, … Never branch on it: IDA fills
    /// this with `AU_*` constants and the two vocabularies are unrelated.
    pub engine_state: String,
    /// What the state above means for the answer it rides on.
    pub note: String,
}

/// [`AnalysisCoverage::state`], in three cases.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisCoverageState {
    /// Analysis had settled: this is Binary Ninja's final answer.
    Complete,
    /// Analysis had not settled: the answer is a lower bound.
    Partial,
    /// Completeness could not be determined. Treat exactly as `Partial`; it is
    /// spelled differently only so "still working" and "no idea" stay apart.
    Unknown,
}

/// Read coverage off a view.
///
/// `complete` is `state == IdleState` with nothing in `active_info` — which is
/// the point [`BinaryViewExt::update_analysis_and_wait`] returns at, so under
/// normal operation this reports `Complete`. It earns its place in the two cases
/// where that is false and nothing else would say so: analysis was aborted
/// (`analysis_is_aborted`), or the view is being held (`HoldState`).
pub fn coverage(view: &BinaryView) -> AnalysisCoverage {
    let info = view.analysis_info();
    let engine_state = format!("{:?}", info.state);
    let aborted = view.analysis_is_aborted();
    let idle = matches!(info.state, BNAnalysisState::IdleState) && info.active_info.is_empty();
    let running = matches!(
        info.state,
        BNAnalysisState::DiscoveryState
            | BNAnalysisState::DisassembleState
            | BNAnalysisState::AnalyzeState
            | BNAnalysisState::ExtendedAnalyzeState
    ) || !info.active_info.is_empty();

    if aborted {
        return AnalysisCoverage {
            complete: false,
            state: AnalysisCoverageState::Partial,
            analysis_running: running,
            engine_state,
            note: "Analysis was aborted before it finished; every count and list here is a \
                   lower bound and re-reading will not improve it. Reopen the view to analyze \
                   again."
                .to_owned(),
        };
    }
    if idle {
        return AnalysisCoverage {
            complete: true,
            state: AnalysisCoverageState::Complete,
            analysis_running: false,
            engine_state,
            note: "Analysis had settled when this was read; the counts and lists are Binary \
                   Ninja's final answer for this view."
                .to_owned(),
        };
    }
    AnalysisCoverage {
        complete: false,
        state: AnalysisCoverageState::Partial,
        analysis_running: running,
        engine_state,
        note: "Analysis had not settled when this was read; every count and list here is a \
               lower bound. Re-read in a moment — Pseudo C for a function may also change \
               until analysis converges."
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    /// A version number that has drifted from the version it names is worse than
    /// none: `doctor` would report a commit this binary was never built against,
    /// and a bug report would send someone to the wrong source.
    #[test]
    fn the_pinned_revision_matches_the_manifest() {
        let manifest = include_str!("../../Cargo.toml");
        let pins = manifest
            .lines()
            .filter(|l| l.contains("rev = \""))
            .filter(|l| l.contains(super::PINNED_API_REVISION))
            .count();
        assert_eq!(
            pins,
            2,
            "PINNED_API_REVISION ({}) must match the `rev` of both binaryninja and \
             binaryninjacore-sys in Cargo.toml",
            super::PINNED_API_REVISION
        );
    }
}
