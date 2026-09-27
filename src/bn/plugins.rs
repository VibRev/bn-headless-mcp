//! Loading a native plugin by path, and hearing what the core says about it.
//!
//! Binary Ninja's C API has no call that loads one named plugin. `BNInitPlugins`
//! walks the bundled directory and, when asked, the user directory; there is
//! nothing in between. So a plugin named with `--plugin` is loaded the way the
//! core's own loader loads one: `dlopen` it, ask `CorePluginABIVersion` whether
//! it was built for this core, and call `CorePluginInit`.
//!
//! **When is the point.** An architecture plugin registers its architecture,
//! its view type and usually an analysis workflow in `CorePluginInit`. All three
//! have to exist before the binary is loaded — view type selection and the first
//! analysis pass both happen inside the load — so [`Engine::open`] calls
//! [`load_native`] after the session initializes and before
//! `load_with_options`. [Measured] loaded in that order, a test plugin's
//! `CorePluginInit` ran and the load that followed saw what it registered.
//!
//! **Never unloaded.** The library handle is leaked on purpose. The core keeps
//! pointers into it — every callback the plugin registered — and calls them
//! until `BNShutdown`, which runs at process exit, after every value this engine
//! owns has been dropped. A `dlclose` before that would leave the core calling
//! into unmapped memory on the way out. One process per view means the leak is
//! bounded by the process, which is also how the memory comes back.
//!
//! [`Engine::open`]: super::Engine::open

use std::path::Path;
use std::sync::Once;

use binaryninja::logger::{register_log_listener, BnLogLevel, LogContext, LogListener};
use binaryninja::tracing::TracingLogListener;
use libloading::os::unix::{Library, Symbol, RTLD_LOCAL, RTLD_NOW};

use crate::error::ToolError;

/// Whether a plugin reporting `plugin_abi` may be loaded into a core that
/// accepts `[minimum, current]`.
///
/// The core applies the same rule to the plugins it loads itself. A plugin
/// newer than the core may call functions the core does not have; one older
/// than the minimum was built against structures the core has since changed.
/// Either way the failure is a crash somewhere later rather than an error here.
pub fn abi_accepted(plugin_abi: u32, minimum: u32, current: u32) -> bool {
    (minimum..=current).contains(&plugin_abi)
}

/// `dlopen` one native plugin, check its ABI, and run its `CorePluginInit`.
///
/// Must run after the core has initialized — the plugin's init calls straight
/// into it — and before the binary is loaded. See the module docs.
pub(super) fn load_native(path: &Path) -> Result<(), ToolError> {
    let shown = path.display();
    let fail = |why: String| ToolError::Bn(format!("plugin {shown}: {why}"));

    // `RTLD_NOW` rather than libloading's default `RTLD_LAZY`: a plugin built
    // against a core that lacks one of its symbols fails here, with the
    // symbol's name, instead of the first time the missing function is called
    // somewhere deep inside analysis.
    //
    // SAFETY: loading a library runs its initializers. That is the point of
    // `--plugin`, and the operator named this file.
    let library = unsafe { Library::open(Some(path), RTLD_NOW | RTLD_LOCAL) }
        .map_err(|e| fail(format!("could not be loaded: {e}")))?;

    // SAFETY: `CorePluginABIVersion` is declared `uint32_t (void)` by
    // `binaryninjaapi.h` and by the Rust API's own export.
    let abi: Symbol<unsafe extern "C" fn() -> u32> =
        unsafe { library.get(b"CorePluginABIVersion\0") }.map_err(|_| {
            fail("exports no CorePluginABIVersion, so it is not a Binary Ninja core plugin".into())
        })?;
    let plugin_abi = unsafe { abi() };
    let (minimum, current) = (
        binaryninja::core_abi_minimum_version(),
        binaryninja::core_abi_version(),
    );
    if !abi_accepted(plugin_abi, minimum, current) {
        return Err(fail(format!(
            "built for core ABI {plugin_abi}, and this core accepts {minimum}..={current}. \
             Rebuild it against Binary Ninja API revision {}, the one this engine is pinned to",
            super::PINNED_API_REVISION
        )));
    }

    // A dependency declaration is a request to the core's loader to order this
    // plugin after another one. That loader is not the one running now, so the
    // declaration cannot be honoured; what can satisfy it is a bundled plugin
    // (already loaded by the time this runs) or an earlier `--plugin`. Said
    // rather than guessed at: a missing dependency shows up as a missing
    // architecture or view type, far from its cause.
    //
    // SAFETY: only the symbol's presence is checked; it is never called.
    if unsafe { library.get::<unsafe extern "C" fn()>(b"CorePluginDependencies\0") }.is_ok() {
        tracing::warn!(
            plugin = %shown,
            "declares CorePluginDependencies, which a plugin loaded by path cannot have \
             honoured: only bundled plugins and earlier --plugin entries are loaded before it"
        );
    }

    // SAFETY: `CorePluginInit` is declared `bool (void)`; C `bool` and Rust
    // `bool` share a representation.
    let init: Symbol<unsafe extern "C" fn() -> bool> = unsafe { library.get(b"CorePluginInit\0") }
        .map_err(|_| fail("exports no CorePluginInit".into()))?;
    if !unsafe { init() } {
        return Err(fail(
            "CorePluginInit returned false (the plugin refused to initialize; its own log \
             lines above say why)"
                .into(),
        ));
    }

    // See the module docs: the core holds pointers into this library until
    // process exit.
    std::mem::forget(library);
    tracing::info!(plugin = %shown, abi = plugin_abi, "loaded native plugin");
    Ok(())
}

/// Forward the core's log to this process's tracing subscriber, once.
///
/// Without it nothing the core logs is visible anywhere: a plugin that fails to
/// load, a view type that rejects the file, a workflow that throws — all of it
/// goes to a log nobody is listening to. With it, those lines land on the
/// worker's stderr, which the supervisor relays tagged with the view.
///
/// Registered before the session initializes, so that what the core says while
/// it loads plugins is heard too. The listener's own threshold is read off the
/// subscriber's filter for the `binaryninja` target, so a level the filter would
/// drop is never formatted by the core in the first place.
///
/// Process-lifetime, like the plugins: the guard is not `Send`, the engine is
/// shared across threads, and unregistering at exit would only race the
/// shutdown that follows it.
///
/// One line is dropped on the way — see [`CoreLog`].
pub(super) fn forward_core_log() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let level = if tracing::enabled!(target: "binaryninja", tracing::Level::DEBUG) {
            BnLogLevel::DebugLog
        } else if tracing::enabled!(target: "binaryninja", tracing::Level::INFO) {
            BnLogLevel::InfoLog
        } else if tracing::enabled!(target: "binaryninja", tracing::Level::WARN) {
            BnLogLevel::WarningLog
        } else {
            BnLogLevel::ErrorLog
        };
        std::mem::forget(register_log_listener(CoreLog(
            TracingLogListener::new_with_lvl(level),
        )));
    });
}

/// The core's log as Binary Ninja's own `TracingLogListener` forwards it, minus
/// the one warning every worker would otherwise print on every start.
///
/// "User plugins disabled from command-line override" is the core noticing that
/// `user_plugins` is off — the default this engine picks on purpose, and the
/// state `--user-plugins` exists to change. At warning level it is the only
/// line a normal worker start forwards, so leaving it in would put a warning at
/// the top of every view's log that means "working as configured", and teach
/// operators to read past the warnings that do not.
struct CoreLog(TracingLogListener);

/// The core's wording, matched exactly: anything else it says goes through.
const USER_PLUGINS_OFF: &str = "User plugins disabled from command-line override";

impl LogListener for CoreLog {
    fn log(&self, ctx: &LogContext, level: BnLogLevel, message: &str) {
        if message == USER_PLUGINS_OFF {
            return;
        }
        self.0.log(ctx, level, message);
    }

    fn level(&self) -> BnLogLevel {
        self.0.level()
    }
}

#[cfg(test)]
mod tests {
    use super::abi_accepted;

    #[test]
    fn a_plugin_is_accepted_only_inside_the_cores_window() {
        assert!(abi_accepted(164, 164, 164));
        assert!(abi_accepted(160, 158, 164));
        assert!(!abi_accepted(165, 164, 164), "newer than the core");
        assert!(
            !abi_accepted(157, 158, 164),
            "older than the core's minimum"
        );
    }
}
