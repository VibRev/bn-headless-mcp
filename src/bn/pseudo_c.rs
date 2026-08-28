//! Pseudo C, via `LinearViewObject`.
//!
//! **This route is a deliberate hedge, not a convenience.** Upstream issue #7731
//! is a large MLIL/HLIL binding rewrite, so an engine built on HLIL AST traversal
//! would have to be rewritten with it. `LinearViewObject::language_representation`
//! asks the core for rendered text instead, which is the same path Binary Ninja's
//! own `examples/decompile.rs` takes and the one that came through 20 s of
//! hammering across 8 threads intact. Fewer of our lines sit on top of the churn.
//!
//! The cursor dance below (seek to the function's highest address, take the lines
//! before it and the lines after it) comes from that example. It is not obvious,
//! and it is not ours to improve: a linear view is a flat stream of the whole
//! binary, so extracting one function means bracketing it.

use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::disassembly::{DisassemblyOption, DisassemblySettings};
use binaryninja::function::Function;
use binaryninja::linear_view::LinearViewObject;

/// Render one function as pseudocode text.
///
/// `language` is one of the names the core advertises — this install reports
/// `["Pseudo C", "Pseudo Objective-C", "Pseudo Rust"]`. An unknown name does not
/// error; the core falls back, which is why the caller-facing parameter is an
/// enum rather than a free string.
///
/// `WaitForIL` is the option that matters: without it the core will hand back
/// whatever IL exists at this instant, which is exactly the non-determinism this
/// module exists to shut out (the same function rendering 1876 then 1836
/// characters). Combined with [`Engine::read`](super::Engine::read) settling
/// analysis first, a given view answers the same question the same way.
///
/// The function header is left on. `Rendered<T>`'s "lone text key" rule means
/// this payload has to be a single `c_code` field to print
/// as bare source instead of escaped JSON, so the header is the only place the
/// signature can live.
pub fn render(view: &BinaryView, func: &Function, language: &str) -> String {
    let settings = DisassemblySettings::new();
    settings.set_option(DisassemblyOption::ShowAddress, false);
    settings.set_option(DisassemblyOption::WaitForIL, true);
    settings.set_option(DisassemblyOption::IndentHLILBody, false);
    settings.set_option(DisassemblyOption::ShowCollapseIndicators, false);
    settings.set_option(DisassemblyOption::ShowFunctionHeader, true);

    let linear_view = LinearViewObject::language_representation(view, &settings, language);
    let mut cursor = linear_view.create_cursor();
    cursor.seek_to_address(func.highest_address());

    // `get_next_*` advances the cursor, so the tail is taken from a duplicate and
    // the head from the original — reversing this order silently returns nothing.
    let tail = view.get_next_linear_disassembly_lines(&mut cursor.duplicate());
    let head = view.get_previous_linear_disassembly_lines(&mut cursor);

    head.into_iter()
        .chain(&tail)
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}
