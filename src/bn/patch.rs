//! Patching, through the C API the Rust bindings do not reach.
//!
//! The Rust API wraps `Architecture::convert_to_nop` and friends, but those are
//! the *trait* methods a custom architecture implements: they take a byte
//! buffer and never touch a view. The functions that patch a `BinaryView` —
//! `BNConvertToNop(view, arch, addr)` and the rest — are in the core header with
//! no Rust wrapper, so this module reaches for them directly, the same way
//! [`super::script`] reaches for the scripting provider.
//!
//! # `never_branch` is one call and two questions
//!
//! Binary Ninja's Python API gives this two names, `convert_to_nop` and
//! `never_branch`, but the *action* is one call: there is no `BNNeverBranch` in
//! the header, and Python's `never_branch` forwards to `BNConvertToNop`. So this
//! ships one tool, `patch.nop`, and its description says so for whoever comes
//! looking for the other name.
//!
//! The *query* is not one call, and getting that wrong produces exactly the kind
//! of plausible-but-wrong answer this engine is careful about.
//! `BNIsNeverBranchPatchAvailable` asks "is this a branch I could neutralize",
//! not "can this instruction be NOPed" — [measured] it answers `false` for
//! `push rbp`, and `BNConvertToNop` then NOPs it anyway. So
//! [`Availability::can_nop`] is derived from whether anything decodes at all,
//! and the branch question keeps its own field.
//!
//! # Nothing here reaches the disk
//!
//! Every patch is a write to the in-memory view. `database.create_bndb` is what
//! persists analysis *and* patches; `database.export_binary` is what writes the
//! patched bytes back out as a runnable file. A worker that exits without one of
//! those has changed nothing on disk, which is the same rule the annotation
//! tools follow.

use std::ffi::{CStr, CString};

use binaryninja::binary_view::{BinaryView, BinaryViewBase};
use binaryninjacore_sys::*;

use crate::error::ToolError;
use crate::server::responses::PatchOperation;

/// The architecture to patch `addr` with.
///
/// The function's own architecture where there is a function — a view's default
/// is wrong the moment a binary mixes ARM and Thumb, and that is exactly the
/// case where a mis-assembled patch is hardest to notice.
///
/// **The returned handle is borrowed and must never be freed.** The core owns
/// every `BNArchitecture` for the life of the process: there is no
/// `BNFreeArchitecture` in the header, the Rust `CoreArchitecture` wrapper has no
/// `Drop`, and upstream still carries a TODO noting architectures are never
/// freed. Every caller below therefore drops the pointer on the floor, which
/// looks like a leak and is not one — adding a free would be a double free.
fn architecture(view: &BinaryView, addr: u64) -> Result<*mut BNArchitecture, ToolError> {
    // `Function::handle` is private in the Rust API, so the function list comes
    // through the C API too rather than half of this going one way and half the
    // other.
    let mut count = 0usize;
    let arch = unsafe {
        let functions = BNGetAnalysisFunctionsContainingAddress(view.handle, addr, &mut count);
        let arch = (!functions.is_null() && count > 0)
            .then(|| BNGetFunctionArchitecture(*functions))
            .filter(|a| !a.is_null());
        if !functions.is_null() {
            BNFreeFunctionList(functions, count);
        }
        arch
    };
    if let Some(arch) = arch {
        return Ok(arch);
    }
    let arch = unsafe { BNGetDefaultArchitecture(view.handle) };
    if arch.is_null() {
        Err(ToolError::Bn(
            "the view has no default architecture, so there is nothing to patch with".to_owned(),
        ))
    } else {
        Ok(arch)
    }
}

/// Length of the instruction at `addr`, or 0 when nothing decodes there.
pub fn instruction_length(view: &BinaryView, addr: u64) -> usize {
    let Ok(arch) = architecture(view, addr) else {
        return 0;
    };
    unsafe { BNGetInstructionLength(view.handle, arch, addr) }
}

/// Which patches Binary Ninja will accept at `addr`.
///
/// Asked rather than attempted: `BNAlwaysBranch` on a non-branch returns false
/// with nothing written, and a caller that cannot tell "refused" from "did
/// nothing" will retry forever.
pub struct Availability {
    pub instruction_length: usize,
    /// Anything that decodes can be NOPed. See the module docs for why this is
    /// *not* `BNIsNeverBranchPatchAvailable`.
    pub can_nop: bool,
    /// This is a branch, so `patch.nop` here means "never taken".
    pub can_never_branch: bool,
    pub can_always_branch: bool,
    pub can_invert_branch: bool,
    pub can_skip_and_return: bool,
    pub can_assemble: bool,
}

pub fn availability(view: &BinaryView, addr: u64) -> Result<Availability, ToolError> {
    let arch = architecture(view, addr)?;
    Ok(unsafe {
        let instruction_length = BNGetInstructionLength(view.handle, arch, addr);
        Availability {
            instruction_length,
            can_nop: instruction_length > 0,
            can_never_branch: BNIsNeverBranchPatchAvailable(view.handle, arch, addr),
            can_always_branch: BNIsAlwaysBranchPatchAvailable(view.handle, arch, addr),
            can_invert_branch: BNIsInvertBranchPatchAvailable(view.handle, arch, addr),
            can_skip_and_return: BNIsSkipAndReturnValuePatchAvailable(view.handle, arch, addr),
            can_assemble: BNCanAssemble(view.handle, arch),
        }
    })
}

/// Apply one of the structured patches.
///
/// Returns `false` when Binary Ninja declined, which it does by writing nothing
/// — the caller gets a refusal, not a silent no-op.
pub fn apply(
    view: &BinaryView,
    addr: u64,
    op: PatchOperation,
    value: u64,
) -> Result<bool, ToolError> {
    let arch = architecture(view, addr)?;
    Ok(unsafe {
        match op {
            PatchOperation::Nop => BNConvertToNop(view.handle, arch, addr),
            PatchOperation::AlwaysBranch => BNAlwaysBranch(view.handle, arch, addr),
            PatchOperation::InvertBranch => BNInvertBranch(view.handle, arch, addr),
            PatchOperation::SkipAndReturn => BNSkipAndReturnValue(view.handle, arch, addr, value),
        }
    })
}

/// Assemble `code` for the architecture at `addr`.
///
/// The assembler's own error text is passed through: "invalid operand" from
/// yasm says more than anything this layer could invent.
pub fn assemble(view: &BinaryView, addr: u64, code: &str) -> Result<Vec<u8>, ToolError> {
    let arch = architecture(view, addr)?;
    if !unsafe { BNCanAssemble(view.handle, arch) } {
        return Err(ToolError::Bn(
            "this architecture has no assembler in this Binary Ninja install".to_owned(),
        ));
    }
    let source = CString::new(code)
        .map_err(|_| ToolError::InvalidParams("code contains a NUL byte".to_owned()))?;

    // SAFETY: `BNAssemble` fills `buffer` on success and `errors` on failure;
    // both are owned by this function from here on, and every path below frees
    // them.
    let buffer = unsafe { BNCreateDataBuffer(std::ptr::null(), 0) };
    if buffer.is_null() {
        return Err(ToolError::Bn(
            "Binary Ninja could not allocate an assembly buffer".to_owned(),
        ));
    }
    let mut errors: *mut std::os::raw::c_char = std::ptr::null_mut();
    let ok = unsafe { BNAssemble(arch, source.as_ptr(), addr, buffer, &mut errors) };

    let message = if errors.is_null() {
        String::new()
    } else {
        let text = unsafe { CStr::from_ptr(errors) }
            .to_string_lossy()
            .into_owned();
        unsafe { BNFreeString(errors) };
        text
    };

    if !ok {
        unsafe { BNFreeDataBuffer(buffer) };
        let detail = if message.trim().is_empty() {
            "the assembler refused it and said nothing".to_owned()
        } else {
            message.trim().to_owned()
        };
        return Err(ToolError::InvalidParams(format!(
            "could not assemble {code:?} at {addr:#x}: {detail}"
        )));
    }

    let bytes = unsafe {
        let len = BNGetDataBufferLength(buffer);
        let data = BNGetDataBufferContents(buffer) as *const u8;
        let out = if data.is_null() || len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data, len).to_vec()
        };
        BNFreeDataBuffer(buffer);
        out
    };
    if bytes.is_empty() {
        return Err(ToolError::InvalidParams(format!(
            "{code:?} assembled to nothing at {addr:#x}"
        )));
    }
    Ok(bytes)
}

/// The architecture's NOP encoding at `addr`, for padding a short patch.
///
/// Assembled rather than hardcoded — `0x90` is x86's and nothing else's. Returns
/// `None` when the architecture has no assembler or its NOP is not one byte, in
/// which case the caller must say it could not pad rather than guess.
pub fn nop_byte(view: &BinaryView, addr: u64) -> Option<u8> {
    match assemble(view, addr, "nop") {
        Ok(bytes) if bytes.len() == 1 => Some(bytes[0]),
        _ => None,
    }
}

/// Write bytes into the view, refusing a short write.
///
/// `BNWrite` returns how many bytes landed, and a partial write across the end
/// of a segment is the interesting failure: half a patched instruction is worse
/// than an unpatched one, and the return value is the only place it shows up.
pub fn write(view: &BinaryView, addr: u64, bytes: &[u8]) -> Result<usize, ToolError> {
    let written = view.write(addr, bytes);
    if written == bytes.len() {
        Ok(written)
    } else {
        Err(ToolError::Bn(format!(
            "wrote {written} of {} bytes at {addr:#x}; the view is not writable that far. \
             The first {written} bytes were written and were not rolled back — re-read \
             before patching again.",
            bytes.len()
        )))
    }
}

/// Write the patched contents out as a file.
///
/// Not a `.bndb`: this is the binary itself, with every patch applied, in the
/// format it was loaded from. `database.create_bndb` saves the analysis;
/// this saves the artifact.
pub fn export_binary(view: &BinaryView, path: &str) -> Result<bool, ToolError> {
    let path = CString::new(path)
        .map_err(|_| ToolError::InvalidParams("path contains a NUL byte".to_owned()))?;
    Ok(unsafe { BNSaveToFilename(view.handle, path.as_ptr()) })
}

/// The `FileMetadata` behind a view.
///
/// `FileMetadata::handle` is `pub(crate)` in the Rust API, so the undo calls
/// below take the raw pointer from the core instead of going through the
/// wrapper. `BNGetFileForView` returns a new reference; the caller frees it.
fn file_metadata(view: &BinaryView) -> *mut BNFileMetadata {
    unsafe { BNGetFileForView(view.handle) }
}

/// One entry on the undo stack, as Binary Ninja describes it.
///
/// The entry's id is deliberately not carried. `BNRevertUndoActions(id)` reads
/// like a targeted revert built on exactly that, and [measured] it is a **silent
/// no-op** on any transaction that already has a newer one above it — no error,
/// no return value, nothing undone. Keeping the id here would invite someone to
/// build that broken feature; undo is last-in-first-out and this type says so by
/// omission.
pub struct UndoEntry {
    /// One line per action, e.g. `Wrote data of length 0x1 at offset 0x2040`.
    ///
    /// This is the only way to know what an entry contains without undoing it,
    /// which is what lets `patch.revert` refuse an entry that is not a patch.
    pub actions: Vec<String>,
}

impl UndoEntry {
    /// True when every action in this entry is a write to the view's data.
    ///
    /// Conservative on purpose: an entry mixing a patch with anything else is
    /// not a patch entry, because undoing it would take the other thing back
    /// too and the caller only asked about the patch.
    pub fn is_only_data_writes(&self) -> bool {
        !self.actions.is_empty()
            && self
                .actions
                .iter()
                .all(|action| action.starts_with("Wrote data of length"))
    }
}

fn take_string(raw: *mut std::os::raw::c_char) -> String {
    if raw.is_null() {
        return String::new();
    }
    unsafe {
        let text = CStr::from_ptr(raw).to_string_lossy().into_owned();
        BNFreeString(raw);
        text
    }
}

/// The undo stack, oldest first. Empty when there is nothing to undo.
pub fn undo_entries(view: &BinaryView) -> Vec<UndoEntry> {
    let file = file_metadata(view);
    if file.is_null() {
        return Vec::new();
    }
    let mut count = 0usize;
    let mut out = Vec::new();
    unsafe {
        let entries = BNGetUndoEntries(file, &mut count);
        if !entries.is_null() {
            for i in 0..count {
                let entry = *entries.add(i);
                if entry.is_null() {
                    continue;
                }
                let mut action_count = 0usize;
                let actions_raw = BNUndoEntryGetActions(entry, &mut action_count);
                let mut actions = Vec::new();
                if !actions_raw.is_null() {
                    for j in 0..action_count {
                        let action = *actions_raw.add(j);
                        if !action.is_null() {
                            actions.push(take_string(BNUndoActionGetSummaryText(action)));
                        }
                    }
                    BNFreeUndoActionList(actions_raw, action_count);
                }
                out.push(UndoEntry { actions });
            }
            BNFreeUndoEntries(entries, count);
        }
        BNFreeFileMetadata(file);
    }
    out
}

/// Open an undo transaction, returning the id to close it with.
///
/// Every patch runs inside one, for two measured reasons. Without a bracket the
/// core still records the write, but the entry does not appear on the stack for
/// about 50 ms — `BNCanUndo` and `BNGetUndoEntries` both report "nothing here"
/// in that window, so a revert issued straight after a patch would read an empty
/// stack and answer wrongly. With a bracket the entry is visible the instant
/// `commit` returns. The bracket also makes a multi-step patch one entry:
/// `patch.assemble` writes the instruction and then the NOP padding, and undoing
/// half of that is not a state anyone asked for.
pub fn begin_undo(view: &BinaryView) -> Option<String> {
    let file = file_metadata(view);
    if file.is_null() {
        return None;
    }
    let id = take_string(unsafe { BNBeginUndoActions(file, false) });
    unsafe { BNFreeFileMetadata(file) };
    (!id.is_empty()).then_some(id)
}

pub fn commit_undo(view: &BinaryView, id: &str) {
    let Ok(id) = CString::new(id) else { return };
    let file = file_metadata(view);
    if file.is_null() {
        return;
    }
    unsafe {
        BNCommitUndoActions(file, id.as_ptr());
        BNFreeFileMetadata(file);
    }
}

/// Undo the newest entry. False when the stack was empty.
pub fn undo(view: &BinaryView) -> bool {
    let file = file_metadata(view);
    if file.is_null() {
        return false;
    }
    unsafe {
        let ok = BNUndo(file);
        BNFreeFileMetadata(file);
        ok
    }
}
