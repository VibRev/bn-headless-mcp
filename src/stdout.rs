//! Take file descriptor 1 away from everything but this engine's own output.
//!
//! A worker speaks JSON-RPC on its stdout, and `tool` prints its answer there.
//! Both share the process with code this engine does not control: the Binary
//! Ninja core, every native plugin it loads, and whatever a `script.python`
//! caller submits. Any of those can write to fd 1 directly — a plugin's `printf`
//! in `CorePluginInit`, `os.write(1, ...)` from a script — and fd 1 is the
//! protocol stream.
//!
//! [Measured] a native plugin whose `CorePluginInit` calls `printf` puts its line
//! ahead of the worker's `initialize` response. rmcp's client happened to skip
//! that one because it was a whole line arriving before the first message; a
//! write without a newline lands in front of the next message instead and
//! corrupts it, and on the `tool` path it is simply in the answer, which breaks
//! the byte-for-byte guarantee `tests/two_paths.rs` holds.
//!
//! So before anything else runs, the real stdout is moved to a private
//! descriptor that only this engine writes to, and fd 1 is pointed at stderr. A
//! stray write still goes *somewhere* an operator can read — the supervisor
//! relays every worker's stderr — it just no longer goes into the protocol.
//!
//! Python's `print()` never needed this: Binary Ninja replaces `sys.stdout` with
//! a writer that feeds its output listener. This is for everything that goes
//! around that.

use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;

/// Move the real stdout to a private descriptor and point fd 1 at stderr.
///
/// Returns the only handle that still reaches the original stdout. Call it
/// before Binary Ninja is initialized and before anything else writes to
/// stdout: whatever is buffered in Rust's `std::io::stdout()` at that point
/// would follow fd 1 to stderr.
///
/// The duplicate is `FD_CLOEXEC` and numbered above 2, so it neither leaks into
/// processes a script spawns nor collides with stdin, stdout or stderr.
pub fn reserve() -> io::Result<File> {
    // SAFETY: plain descriptor syscalls on descriptors this process owns; the
    // new descriptor is handed to exactly one `File`, which becomes its owner.
    unsafe {
        let private = libc::fcntl(libc::STDOUT_FILENO, libc::F_DUPFD_CLOEXEC, 3);
        if private < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) < 0 {
            let error = io::Error::last_os_error();
            libc::close(private);
            return Err(error);
        }
        Ok(File::from_raw_fd(private))
    }
}
