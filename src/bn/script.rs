//! Python, in this process, against the same `BinaryView` every other tool reads.
//!
//! Binary Ninja registers exactly one scripting provider in a headless Rust
//! process — `name="Python" api="python3"` — and it is reachable through the C
//! API even though the Rust API wraps none of it. `BNSetScriptingInstanceCurrentBinaryView`
//! binds the console's `bv` to *our* view, so a script sees the analysis this
//! worker already paid for and its writes are visible to the other tools
//! immediately. [Measured] renaming the entry point from Python and reading the
//! name back through `BinaryViewExt::functions` agrees, in 0.30 s.
//!
//! # Why every submission is one physical line
//!
//! `BNExecuteScriptInput` feeds a **console**, not `exec()`. It compiles input
//! the way a REPL does, so a plain multi-statement script fails exactly the way
//! pasting it into `python3` would:
//!
//! ```text
//! for i in range(3):
//!     pass
//! print("done")        <- SyntaxError: invalid syntax
//! ```
//!
//! Worse, the failed compound statement leaves the console mid-block, and the
//! *next* submission is silently swallowed as continuation input — a script that
//! never runs and never reports anything. [Measured] both.
//!
//! So the real source travels as base64 inside a single physical line, and a
//! runner installed once does the `compile`/`exec`. The console never sees more
//! than one statement at a time and there is nothing for it to buffer.
//!
//! # How the answer comes back
//!
//! Output arrives through `BNScriptingOutputListener`, fragmented — one callback
//! per `print` *argument*, not per line. Parsing that stream is not viable, so
//! the runner captures the script's own stdout/stderr inside Python, builds one
//! JSON object, and writes it between two sentinels. The Rust side accumulates
//! every fragment and cuts the payload out. Anything the script printed is
//! inside that JSON, not interleaved with it.
//!
//! # The one thing a script must not do
//!
//! This worker speaks MCP over its real stdout. `print()` is safe — Binary Ninja
//! replaces `sys.stdout` with a writer that feeds the listener, and [measured]
//! nothing leaks to file descriptor 1. `os.write(1, ...)` and `sys.__stdout__`
//! are not safe: they write straight into the JSON-RPC stream and end the
//! session. There is no way to prevent that from inside the process, so it is
//! documented on the tool instead.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use binaryninja::binary_view::BinaryView;
use binaryninjacore_sys::*;

use crate::error::ToolError;

/// Wraps the JSON the runner emits. Chosen to be improbable in real output; if a
/// script prints it anyway, the first opener and the *last* closer still bracket
/// the real payload, because the runner writes its object last and exactly once.
const BEGIN: &str = "<<<BN_MCP_RESULT[";
const END: &str = "]BN_MCP_RESULT>>>";

/// Every submission carries one of these, and only its own payload is accepted.
///
/// Without it a timed-out run poisons the *next* one. `KeyboardInterrupt` is
/// delivered between bytecodes, so a script blocked inside a Binary Ninja core
/// call does not take it — the run gives up, releases the engine lock, and the
/// caller sends another script. Binary Ninja's console is one serial
/// interpreter, so the new script queues behind the old one; the old one
/// finishes, writes its sentinel, and the new run's reader finds it. The second
/// caller would get the first caller's `stdout` and `result` reported as their
/// own. Not an error — a wrong answer, which is the failure this engine spends
/// most of its design on avoiding.
static NEXT_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_nonce() -> u64 {
    NEXT_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// How much captured stdout the runner will hand back, in characters.
const STDOUT_LIMIT: usize = 256 * 1024;

/// A payload shaped like the runner's, for the two submissions that have no
/// script to report on. Keeping the shape identical is what lets one sentinel
/// reader serve setup, reset and every run.
fn ack_json(nonce: u64) -> String {
    format!(
        r#"{{"nonce": {nonce}, "ok": true, "stdout": "", "result": null, "error": null, "truncated": false}}"#
    )
}

/// Longest a script may run before it is interrupted, unless the caller says
/// otherwise.
///
/// Typed to the wire rather than to `Duration::from_secs`: these two bound a
/// number the caller sends, and the caller sends `i64` (see `ScriptArgs`).
pub const DEFAULT_TIMEOUT_SECS: i64 = 60;
/// Ceiling on the caller's timeout.
pub const MAX_TIMEOUT_SECS: i64 = 600;

/// Installed once per console. Everything after this is a call into it.
///
/// `result` is popped before each run so a value left behind by the *previous*
/// script is never reported as this one's answer.
const RUNNER_SOURCE: &str = r#"
def __bn_mcp_run(src_b64, begin, end, limit, nonce):
    import base64, io, json, contextlib, traceback, sys
    g = globals()
    g.pop('result', None)
    out = {"nonce": nonce, "ok": False, "stdout": "", "result": None,
           "error": None, "truncated": False}
    buf = io.StringIO()
    try:
        src = base64.b64decode(src_b64).decode('utf-8')
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            exec(compile(src, '<mcp-script>', 'exec'), g)
        out["ok"] = True
        if 'result' in g:
            r = g['result']
            try:
                json.dumps(r)
                out["result"] = r
            except (TypeError, ValueError):
                out["result"] = repr(r)
    except BaseException:
        out["error"] = traceback.format_exc()
    text = buf.getvalue()
    if len(text) > limit:
        text = text[:limit]
        out["truncated"] = True
    out["stdout"] = text
    sys.stdout.write(begin + json.dumps(out) + end + "\n")
    sys.stdout.flush()

def __bn_mcp_reset(begin, end, nonce):
    import json, sys
    g = globals()
    keep = ('bv', 'current_view', 'current_function', 'current_address',
            'current_basic_block', 'current_selection', 'current_llil',
            'current_mlil', 'current_hlil', 'here', 'start', 'bp')
    for k in [k for k in g if not k.startswith('__') and k not in keep]:
        del g[k]
    sys.stdout.write(begin + json.dumps(
        {"nonce": nonce, "ok": True, "stdout": "", "result": None,
         "error": None, "truncated": False}
    ) + end + "\n")
    sys.stdout.flush()
"#;

/// What one script run produced.
pub struct ScriptOutcome {
    pub ok: bool,
    pub stdout: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub truncated: bool,
    pub timed_out: bool,
    pub elapsed_secs: f64,
}

/// Everything the listener callbacks write into.
///
/// Boxed and never moved while the listener is registered: Binary Ninja keeps
/// the raw `context` pointer for the lifetime of the registration.
#[derive(Default)]
struct Capture {
    out: Mutex<String>,
    err: Mutex<String>,
}

impl Capture {
    fn take(&self) -> (String, String) {
        let out = std::mem::take(&mut *self.out.lock().expect("capture mutex"));
        let err = std::mem::take(&mut *self.err.lock().expect("capture mutex"));
        (out, err)
    }
}

unsafe extern "C" fn cb_output(ctxt: *mut c_void, text: *const c_char) {
    append(ctxt, text, true);
}
unsafe extern "C" fn cb_warning(ctxt: *mut c_void, text: *const c_char) {
    append(ctxt, text, false);
}
unsafe extern "C" fn cb_error(ctxt: *mut c_void, text: *const c_char) {
    append(ctxt, text, false);
}
unsafe extern "C" fn cb_ready(_ctxt: *mut c_void, _state: BNScriptingProviderInputReadyState) {}

/// Shared body of the three output callbacks.
///
/// # Safety
/// `ctxt` is the `Capture` pointer this module registered, and `text` is a
/// NUL-terminated string Binary Ninja owns for the duration of the call.
unsafe fn append(ctxt: *mut c_void, text: *const c_char, stdout: bool) {
    if ctxt.is_null() || text.is_null() {
        return;
    }
    let capture = &*(ctxt as *const Capture);
    let fragment = CStr::from_ptr(text).to_string_lossy();
    let slot = if stdout { &capture.out } else { &capture.err };
    if let Ok(mut buf) = slot.lock() {
        // A runaway script must not grow this without bound. But dropping a
        // whole fragment can drop the closing sentinel with it, and then a
        // script that *succeeded* reads as a timeout — so once the cap is
        // reached, only sentinel-bearing fragments are still appended. The
        // runner caps the payload itself, which is what keeps that bounded too.
        let room = buf.len() < STDOUT_LIMIT * 2;
        if room || fragment.contains(END) || fragment.contains(BEGIN) {
            buf.push_str(&fragment);
        }
    }
}

/// One Python console, bound to one view.
pub struct Console {
    instance: *mut BNScriptingInstance,
    /// Registered with Binary Ninja; its address must stay stable, hence the box.
    listener: Box<BNScriptingOutputListener>,
    /// Pointed at by `listener.context`. Declared after it only for reading
    /// order — drop order is handled explicitly in `Drop`.
    capture: Box<Capture>,
}

// SAFETY: the instance pointer is only ever touched behind the `Mutex<Option<Console>>`
// that `Engine` holds, so at most one thread is inside Binary Ninja's scripting
// API at a time. The console itself is thread-affine to nothing: [measured] it
// was created and driven from the main thread and from a blocking-pool thread
// with identical results.
unsafe impl Send for Console {}

impl Console {
    /// Start a Python console and point it at `view`.
    ///
    /// Costs one Python interpreter initialization, so this is called lazily —
    /// a worker that is never asked to run a script never pays it.
    pub fn new(view: &BinaryView) -> Result<Self, ToolError> {
        let api_name = CString::new("python3").expect("literal has no NUL");
        let provider = unsafe { BNGetScriptingProviderByAPIName(api_name.as_ptr()) };
        if provider.is_null() {
            return Err(ToolError::Bn(
                "Binary Ninja registered no `python3` scripting provider in this process. \
                 Headless Python needs the Python API that ships with the Binary Ninja \
                 install BINARYNINJADIR points at."
                    .to_owned(),
            ));
        }

        let instance = unsafe { BNCreateScriptingProviderInstance(provider) };
        if instance.is_null() {
            return Err(ToolError::Bn(
                "the python3 scripting provider refused to create an instance".to_owned(),
            ));
        }

        let capture = Box::new(Capture::default());
        let mut listener = Box::new(BNScriptingOutputListener {
            context: (&*capture as *const Capture) as *mut c_void,
            output: Some(cb_output),
            warning: Some(cb_warning),
            error: Some(cb_error),
            inputReadyStateChanged: Some(cb_ready),
        });
        unsafe {
            BNRegisterScriptingInstanceOutputListener(instance, listener.as_mut());
            BNSetScriptingInstanceCurrentBinaryView(instance, view.handle);
        }

        let console = Self {
            instance,
            listener,
            capture,
        };

        // The interpreter boots while it imports the Binary Ninja API. This is
        // the one wait that cannot key off a sentinel — nothing has been
        // submitted yet — so it polls the state directly.
        if !console.wait_for_input_ready(Duration::from_secs(120)) {
            return Err(ToolError::Bn(
                "the Python interpreter did not become ready within 120 s".to_owned(),
            ));
        }
        console.capture.take();

        // Install the runner, as one line, the same way every later call goes
        // in. The trailing write is the acknowledgement: several simple
        // statements joined by `;` are still one logical line, so the console
        // has nothing to buffer, and an `exec` that raised never reaches it.
        let nonce = next_nonce();
        let setup = format!(
            "exec(compile(__import__('base64').b64decode('{}').decode('utf-8'), \
             '<bn-mcp-runner>', 'exec'), globals()); \
             __import__('sys').stdout.write('{BEGIN}' + {ack:?} + '{END}' + chr(10))",
            base64(RUNNER_SOURCE.as_bytes()),
            ack = ack_json(nonce),
        );
        console.submit(&setup)?;
        if console
            .await_payload(nonce, Duration::from_secs(60))
            .is_none()
        {
            let (_, err) = console.capture.take();
            let detail = if err.trim().is_empty() {
                "it never acknowledged".to_owned()
            } else {
                err.trim().to_owned()
            };
            return Err(ToolError::Bn(format!(
                "the Python console rejected the script runner: {detail}"
            )));
        }
        console.capture.take();
        Ok(console)
    }

    /// Run `source` and return what it printed, what it left in `result`, and
    /// what went wrong.
    pub fn run(&mut self, source: &str, timeout: Duration) -> ScriptOutcome {
        let started = Instant::now();
        self.capture.take();
        let nonce = next_nonce();
        let line = format!(
            "__bn_mcp_run('{}', '{BEGIN}', '{END}', {STDOUT_LIMIT}, {nonce})",
            base64(source.as_bytes())
        );
        if let Err(e) = self.submit(&line) {
            return ScriptOutcome {
                ok: false,
                stdout: String::new(),
                result: None,
                error: Some(e.to_string()),
                truncated: false,
                timed_out: false,
                elapsed_secs: started.elapsed().as_secs_f64(),
            };
        }

        // Completion is the sentinel, not the ready state. Submission is
        // asynchronous, so a fast script can finish before the console is ever
        // *observed* busy; keying off that edge waits out the entire budget for
        // a script that has already returned.
        let mut payload = self.await_payload(nonce, timeout);
        let finished = payload.is_some();
        if !finished {
            // Still executing. `KeyboardInterrupt` lands inside the script, the
            // runner's `except BaseException` catches it, and the payload still
            // arrives — so keep reading rather than giving up. [Measured] the
            // interrupted run comes back with a `KeyboardInterrupt` traceback and
            // the console is usable immediately afterwards.
            unsafe { BNCancelScriptInput(self.instance) };
            payload = self.await_payload(nonce, Duration::from_secs(15));
        }

        let elapsed_secs = started.elapsed().as_secs_f64();
        let (out, err) = self.capture.take();

        let Some(payload) = payload else {
            // No sentinel: the runner never got to write. Report whatever the
            // console said instead of inventing a result.
            let detail = if !err.trim().is_empty() {
                err.trim().to_owned()
            } else if !out.trim().is_empty() {
                out.trim().to_owned()
            } else if finished {
                "the script produced no output and no result".to_owned()
            } else {
                format!("no result after {elapsed_secs:.1} s; the script was interrupted")
            };
            return ScriptOutcome {
                ok: false,
                stdout: String::new(),
                result: None,
                error: Some(detail),
                truncated: false,
                timed_out: !finished,
                elapsed_secs,
            };
        };

        match serde_json::from_str::<RunnerPayload>(&payload) {
            // `find_payload` matched on the raw text; this is the same check
            // against the parsed value, so a `nonce` that appeared inside a
            // script's own output cannot smuggle a payload through.
            Ok(p) if p.nonce != nonce => ScriptOutcome {
                ok: false,
                stdout: String::new(),
                result: None,
                error: Some(format!(
                    "the Python console answered submission {} while this one was {nonce}; \
                     a previous script that outlived its timeout is still producing output. \
                     Call `script.reset`.",
                    p.nonce
                )),
                truncated: false,
                timed_out: !finished,
                elapsed_secs,
            },
            Ok(p) => ScriptOutcome {
                ok: p.ok,
                stdout: p.stdout,
                result: p.result,
                error: p.error,
                truncated: p.truncated,
                timed_out: !finished,
                elapsed_secs,
            },
            Err(e) => ScriptOutcome {
                ok: false,
                stdout: String::new(),
                result: None,
                error: Some(format!(
                    "the script runner emitted something this build cannot read ({e}); \
                     raw payload was {} characters",
                    payload.len()
                )),
                truncated: false,
                timed_out: !finished,
                elapsed_secs,
            },
        }
    }

    /// Forget everything the previous scripts defined.
    ///
    /// Deliberately *not* a teardown of the scripting instance: there is one
    /// Python interpreter per process, and stopping it is not something a later
    /// `BNCreateScriptingProviderInstance` is documented to recover from. Wiping
    /// the console's own globals gets the property that matters — a fresh
    /// namespace — without betting on that.
    pub fn reset(&mut self) -> Result<(), ToolError> {
        self.capture.take();
        let nonce = next_nonce();
        self.submit(&format!("__bn_mcp_reset('{BEGIN}', '{END}', {nonce})"))?;
        let acknowledged = self.await_payload(nonce, Duration::from_secs(30)).is_some();
        let (_, err) = self.capture.take();
        if acknowledged {
            Ok(())
        } else if err.trim().is_empty() {
            Err(ToolError::Bn(
                "resetting the Python namespace did not finish within 30 s".to_owned(),
            ))
        } else {
            Err(ToolError::Bn(err.trim().to_owned()))
        }
    }

    /// Hand one physical line to the console.
    ///
    /// The core's answer is checked rather than discarded. `IncompleteScriptInput`
    /// is the console saying "that was not a whole statement, I have buffered it"
    /// — the exact failure this module's one-line protocol exists to avoid, and
    /// if it ever happens the alternative to reporting it is waiting out the full
    /// timeout for a sentinel that is never coming.
    fn submit(&self, line: &str) -> Result<(), ToolError> {
        // A NUL inside the line would truncate it. Unreachable — base64 cannot
        // produce one and the other callers are literals — but silently dropping
        // the submission would turn it into a timeout instead of an error.
        let c = CString::new(line)
            .map_err(|_| ToolError::Bn("the submission contained a NUL byte".to_owned()))?;
        match unsafe { BNExecuteScriptInput(self.instance, c.as_ptr()) } {
            BNScriptingProviderExecuteResult::SuccessfulScriptExecution => Ok(()),
            BNScriptingProviderExecuteResult::ScriptExecutionCancelled => Err(ToolError::Bn(
                "the Python console cancelled the submission before running it".to_owned(),
            )),
            BNScriptingProviderExecuteResult::IncompleteScriptInput => Err(ToolError::Bn(
                "the Python console buffered the submission as an incomplete statement. \
                 It is now waiting for a continuation line, which this protocol never \
                 sends — call `script.reset` to clear it."
                    .to_owned(),
            )),
            BNScriptingProviderExecuteResult::InvalidScriptInput => Err(ToolError::Bn(
                "the Python console rejected the submission as invalid input".to_owned(),
            )),
        }
    }

    fn state(&self) -> BNScriptingProviderInputReadyState {
        unsafe { BNGetScriptingInstanceInputReadyState(self.instance) }
    }

    /// Block until the interpreter will accept input at all.
    ///
    /// Only used once, at startup: every later wait keys off the sentinel
    /// instead, because "is the console idle" cannot distinguish *finished* from
    /// *not started yet*.
    fn wait_for_input_ready(&self, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            if !matches!(
                self.state(),
                BNScriptingProviderInputReadyState::NotReadyForInput
            ) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Wait for the runner's JSON to appear in the accumulated output.
    ///
    /// This is the completion signal for every submission. Nothing else is
    /// reliable: `BNExecuteScriptInput` returns before the script runs, and the
    /// output callbacks trail the ready-state change.
    fn await_payload(&self, nonce: u64, budget: Duration) -> Option<String> {
        let deadline = Instant::now() + budget;
        loop {
            if let Some(found) = self.find_payload(nonce) {
                return Some(found);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The payload belonging to `nonce`, if it has arrived.
    ///
    /// Scans every sentinel pair in the buffer rather than only the first,
    /// because a run that timed out can still deliver its own payload later, on
    /// top of whichever run is now reading. Only the one carrying this
    /// submission's nonce is ours.
    fn find_payload(&self, nonce: u64) -> Option<String> {
        let buf = self.capture.out.lock().ok()?;
        payload_for(&buf, nonce)
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        unsafe {
            BNUnregisterScriptingInstanceOutputListener(self.instance, self.listener.as_mut());
            BNFreeScriptingInstance(self.instance);
        }
        // `capture` outlived the registration above, which is the only ordering
        // that matters: the callbacks dereference it until the unregister
        // returns.
    }
}

/// The runner's JSON, before it becomes a [`ScriptOutcome`].
#[derive(serde::Deserialize)]
struct RunnerPayload {
    nonce: u64,
    ok: bool,
    stdout: String,
    result: Option<serde_json::Value>,
    error: Option<String>,
    truncated: bool,
}

/// The payload belonging to `nonce`, out of everything the console has said.
///
/// Scans every sentinel pair rather than only the first, because a run that
/// outlived its timeout can still deliver its own payload later, on top of
/// whichever run is now reading. Only the one carrying this submission's nonce
/// is ours; the rest is someone else's answer and must not be returned as this
/// caller's.
fn payload_for(buf: &str, nonce: u64) -> Option<String> {
    let marker = format!("\"nonce\": {nonce}");
    let mut rest = buf;
    while let Some(open) = rest.find(BEGIN) {
        let body_start = open + BEGIN.len();
        // An opener with no closer yet: the payload is still arriving in
        // fragments, so there is nothing further to find this round.
        let close = rest[body_start..].find(END)?;
        let body = &rest[body_start..body_start + close];
        if body.contains(&marker) {
            return Some(body.to_owned());
        }
        rest = &rest[body_start + close + END.len()..];
    }
    None
}

/// Standard base64, no line breaks.
///
/// Hand-rolled rather than pulled in as a dependency: it is the only encoding
/// this crate needs, the alphabet is fixed by RFC 4648, and the test below pins
/// it against the vectors from that RFC.
fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let bits = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(bits >> 18) as usize & 0x3f] as char);
        out.push(TABLE[(bits >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(bits >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[bits as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64;

    /// The nonce is what stops a timed-out run's answer being handed to the
    /// caller after it. Without this the second caller gets the first caller's
    /// `stdout` and `result` reported as their own — a wrong answer, not an
    /// error.
    #[test]
    fn a_payload_is_only_matched_to_its_own_submission() {
        let begin = super::BEGIN;
        let end = super::END;
        let stale = format!("{begin}{{\"nonce\": 7, \"ok\": true, \"stdout\": \"old\"}}{end}\n");
        let mine = format!("{begin}{{\"nonce\": 8, \"ok\": true, \"stdout\": \"new\"}}{end}\n");

        // The stale one arrived first and is still in the buffer.
        let buffer = format!("{stale}{mine}");
        let found = super::payload_for(&buffer, 8).expect("our payload is there");
        assert!(found.contains("\"stdout\": \"new\""), "{found}");
        assert!(!found.contains("old"), "{found}");

        // Ours has not arrived yet: nothing is returned, rather than the other one.
        assert_eq!(super::payload_for(&stale, 8), None);

        // And the stale one is still findable by its own submission, so this is
        // matching rather than just preferring the last.
        let found = super::payload_for(&buffer, 7).expect("the older payload is still there");
        assert!(found.contains("\"stdout\": \"old\""), "{found}");
    }

    /// A half-arrived payload must not be returned as a whole one. Output comes
    /// back fragmented, one callback per `print` argument.
    #[test]
    fn a_payload_missing_its_closer_is_not_a_payload_yet() {
        let partial = format!("{}{{\"nonce\": 3, \"ok\": true", super::BEGIN);
        assert_eq!(super::payload_for(&partial, 3), None);
    }

    /// RFC 4648 §10. The encoder is the only thing standing between a script's
    /// source and the Python console, so it is pinned rather than eyeballed.
    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    /// The alphabet has no quote, backslash or newline in it, which is the
    /// property that lets a script be interpolated into a single-quoted Python
    /// literal on one physical line without any escaping at all.
    #[test]
    fn base64_output_is_safe_inside_a_python_literal() {
        let nasty = "x = '''\n\\ \" ' \r\n'''\nprint('\u{4f60}\u{597d}')\n";
        let encoded = base64(nasty.as_bytes());
        assert!(encoded
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')));
    }

    /// The runner is submitted as one physical line, so it must not contain a
    /// newline once encoded — and the source it carries may.
    #[test]
    fn the_runner_defines_both_entry_points() {
        assert!(super::RUNNER_SOURCE.contains("def __bn_mcp_run("));
        assert!(super::RUNNER_SOURCE.contains("def __bn_mcp_reset("));
        assert!(!base64(super::RUNNER_SOURCE.as_bytes()).contains('\n'));
    }
}
