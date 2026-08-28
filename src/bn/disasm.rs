//! Linear disassembly, via `LinearViewObject`.
//!
//! Same hedge as [`super::pseudo_c`]: the linear view is rendered text from the
//! core, not a walk of HLIL, so this sits on the safe side of #7731, the upstream
//! MLIL/HLIL binding rewrite. The cursor dance is the one in Binary Ninja's
//! `examples/decompile.rs` — seek to the function's highest address, take the
//! lines after the cursor and the lines before it.

use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::disassembly::{DisassemblyOption, DisassemblySettings};
use binaryninja::function::Function;
use binaryninja::linear_view::LinearViewObject;

/// Render one function as a linear disassembly listing.
///
/// Addresses stay on (unlike [`super::pseudo_c::render`]): a listing without
/// addresses is just worse pseudocode. `WaitForIL` is still set so annotations
/// that depend on IL do not flicker while analysis is settling.
pub fn render(view: &BinaryView, func: &Function) -> String {
    let settings = DisassemblySettings::new();
    settings.set_option(DisassemblyOption::ShowAddress, true);
    settings.set_option(DisassemblyOption::WaitForIL, true);
    settings.set_option(DisassemblyOption::ShowCollapseIndicators, false);
    settings.set_option(DisassemblyOption::ShowFunctionHeader, true);

    let linear_view = LinearViewObject::disassembly(view, &settings);
    let mut cursor = linear_view.create_cursor();
    cursor.seek_to_address(func.highest_address());

    let tail = view.get_next_linear_disassembly_lines(&mut cursor.duplicate());
    let head = view.get_previous_linear_disassembly_lines(&mut cursor);

    head.into_iter()
        .chain(&tail)
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// A rendered listing, and whether `limit` is the reason it ends where it does.
pub struct Listing {
    pub text: String,
    /// True when the range held more lines than `limit` allowed through.
    pub truncated: bool,
}

/// Render a linear listing covering `[start, start+length)`.
///
/// Seeks to `start` and takes subsequent lines while `contents.address` is
/// still inside the range and fewer than `limit` lines have been collected.
///
/// One line past the page is rendered and then dropped, which is what makes
/// `truncated` an observation rather than a guess: without it, a listing that
/// stops at `limit` because the range ended and one that stops at `limit` with
/// a thousand instructions behind it are the same string, and a `lines.len() >=
/// limit` test would call the first one truncated. It is the same trick
/// `truncate_chars` uses on string contents.
pub fn render_range(view: &BinaryView, start: u64, length: u32, limit: usize) -> Listing {
    let settings = DisassemblySettings::new();
    settings.set_option(DisassemblyOption::ShowAddress, true);
    settings.set_option(DisassemblyOption::WaitForIL, true);
    settings.set_option(DisassemblyOption::ShowCollapseIndicators, false);
    settings.set_option(DisassemblyOption::ShowFunctionHeader, true);

    let linear_view = LinearViewObject::disassembly(view, &settings);
    let mut cursor = linear_view.create_cursor();
    cursor.seek_to_address(start);

    let end = start.saturating_add(length as u64);
    let ceiling = limit.saturating_add(1);
    let mut lines = Vec::new();
    loop {
        if lines.len() >= ceiling {
            break;
        }
        let batch = view.get_next_linear_disassembly_lines(&mut cursor);
        if batch.is_empty() {
            break;
        }
        let mut stop = false;
        for line in batch.iter() {
            if line.contents.address >= end {
                stop = true;
                break;
            }
            lines.push(line.to_string());
            if lines.len() >= ceiling {
                stop = true;
                break;
            }
        }
        if stop {
            break;
        }
    }
    let truncated = lines.len() > limit;
    lines.truncate(limit);
    Listing {
        text: lines.join("\n"),
        truncated,
    }
}
