//! The worker's MCP surface — and, by the same definitions, the CLI.
//!
//! Every tool here is written once. `#[vibrev_tool_router]` rewrites each
//! `#[vibrev_tool]` into `#[rmcp::tool]` and hands the block to rmcp's own
//! `#[tool_router]`, then derives three more items from the same `Tool` structs:
//! `vibrev_tool_defs()`, `vibrev_cli()` and `vibrev_call()`. The CLI is built from
//! those, in this process, so the two front ends cannot drift — and a tool that
//! forgets `title` or `annotations` does not compile.
//!
//! **Return type.** These return `Result<CallToolResponse, ErrorData>` rather
//! than `Result<Rendered<T>, ErrorData>`, because a failed tool call has to come
//! back as a *successful* response carrying `isError: true`; the `Err` arm is a
//! protocol error whose message the model never sees. The success arm
//! still goes through [`Rendered`], so `content` holds readable text and
//! `structuredContent` holds the typed payload — and `output = "..."` on the
//! attribute is what publishes the `outputSchema` the macro can no longer infer
//! from the signature.

use std::sync::Arc;

use binaryninja::binary_view::BinaryViewExt;
use rmcp::handler::server::tool::IntoCallToolResult;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResponse, ServerCapabilities, ServerInfo};
use rmcp::{tool_handler, ErrorData, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use vibrev_kit::Rendered;
use vibrev_tool_macros::vibrev_tool_router;

use crate::bn::{self, read, Engine};
use crate::error::ToolError;

pub mod responses;

/// Default page size for paged list tools.
const DEFAULT_LIMIT: usize = 100;

/// The largest page any list tool will serve.
const MAX_LIMIT: usize = 10_000;

/// The `offset` / `limit` pair a paged tool takes, in the types it counts in.
///
/// Both arrive as `i64` because a published input schema may not carry a
/// `uint32` — `vibrev_kit::contract::Rule::UnportableFormat` — which leaves the
/// declared `minimum: 0` as the only thing saying `offset` is not negative, and
/// a schema bound is advice a client is free to ignore.
///
/// The two halves are deliberately asymmetric. An absurd `limit` has an answer,
/// so `page::bounds` clamps it. A negative `offset` has none, and casting one to
/// `usize` turns `-5` into a number near `usize::MAX`, which reads back as an
/// empty page — indistinguishable from having paged off the end — so it is
/// refused instead. This wrapper only puts that refusal into this engine's error
/// type, so the thirteen call sites below keep answering with `InvalidParams`.
fn page(offset: Option<i64>, limit: Option<i64>) -> Result<(usize, usize), ToolError> {
    vibrev_kit::page::bounds(offset, limit, DEFAULT_LIMIT, MAX_LIMIT)
        .map_err(|e| ToolError::InvalidParams(e.to_string()))
}

/// One worker's tool surface, bound to the one `BinaryView` its process holds.
#[derive(Clone)]
pub struct BnMcpServer {
    engine: Arc<Engine>,
}

impl BnMcpServer {
    pub fn new(engine: Arc<Engine>) -> Self {
        Self { engine }
    }

    /// The body shared by `patch.nop`, `always_branch`, `invert_branch` and
    /// `skip_and_return`.
    ///
    /// All four are one core call plus the same before/after bookkeeping, and
    /// the only thing that differs is which call. Writing it four times is how
    /// three of them end up missing the settle-before-read-back.
    ///
    /// A refusal from Binary Ninja becomes an error naming what *is* available
    /// there. The core signals "not applicable here" by writing nothing and
    /// returning false, which a caller cannot tell from a successful no-op — so
    /// this is the one place that distinction has to be made.
    async fn structured_patch(
        &self,
        address: &str,
        operation: responses::PatchOperation,
        value: Option<u64>,
    ) -> Result<CallToolResponse, ErrorData> {
        let address = match parse_address(address) {
            Ok(addr) => addr,
            Err(e) => return Ok(e.to_response()),
        };
        let value = value.unwrap_or(0);
        let out = self
            .engine
            .write(move |view| {
                in_one_undo_entry(view, |view| {
                    let before_length = bn::patch::instruction_length(view, address);
                    let width = before_length.max(1);
                    let (bytes_before, listing_before) = patch_snapshot(view, address, width);

                    if !bn::patch::apply(view, address, operation, value)? {
                        let available = bn::patch::availability(view, address)?;
                        let mut offered: Vec<&str> = Vec::new();
                        if available.can_nop {
                            offered.push("nop");
                        }
                        if available.can_always_branch {
                            offered.push("always_branch");
                        }
                        if available.can_invert_branch {
                            offered.push("invert_branch");
                        }
                        if available.can_skip_and_return {
                            offered.push("skip_and_return");
                        }
                        return Err(ToolError::InvalidParams(format!(
                            "Binary Ninja will not apply {} at {} and wrote nothing. Available \
                         there: {}. `patch.available` reports this without attempting it.",
                            patch_operation_name(operation),
                            read::hex(address),
                            if offered.is_empty() {
                                "nothing".to_owned()
                            } else {
                                offered.join(", ")
                            }
                        )));
                    }

                    view.update_analysis_and_wait();
                    let (bytes_after, listing_after) = patch_snapshot(view, address, width);
                    Ok(responses::PatchResult {
                        address: read::hex(address),
                        operation: patch_operation_name(operation).to_owned(),
                        bytes_before,
                        bytes_after,
                        listing_before,
                        listing_after,
                        // Binary Ninja chose and wrote the encoding itself, so the
                        // instruction's whole length is what changed.
                        bytes_written: width,
                        padding_bytes: 0,
                        ok: true,
                        note: None,
                        persistence: PATCH_PERSISTENCE.to_owned(),
                    })
                })
            })
            .await;
        finish(out)
    }
}

/// The `operation` string a [`responses::PatchResult`] reports.
fn patch_operation_name(operation: responses::PatchOperation) -> &'static str {
    match operation {
        responses::PatchOperation::Nop => "nop",
        responses::PatchOperation::AlwaysBranch => "always_branch",
        responses::PatchOperation::InvertBranch => "invert_branch",
        responses::PatchOperation::SkipAndReturn => "skip_and_return",
    }
}

/// Wrap a payload the way the MCP router would.
///
/// Routing the success arm through [`Rendered`] rather than building a
/// `CallToolResult` by hand is what keeps `content[0].text` and the CLI's stdout
/// the *same string* rather than two strings that happen to agree.
fn ok<T: Serialize + JsonSchema + 'static>(value: T) -> Result<CallToolResponse, ErrorData> {
    Rendered(value).into_call_tool_result()
}

/// Collapse a tool-layer failure into the shape a failed tool call has to take:
/// a successful response carrying `isError: true`.
fn finish<T: Serialize + JsonSchema + 'static>(
    outcome: Result<Result<T, ToolError>, ToolError>,
) -> Result<CallToolResponse, ErrorData> {
    match outcome {
        Ok(Ok(value)) => ok(value),
        Ok(Err(e)) | Err(e) => Ok(e.to_response()),
    }
}

/// Which pseudocode dialect to render.
///
/// Binary Ninja 5.3.9757 advertises exactly these three
/// (`language_representation` refuses anything else), and the enum is here
/// rather than a free string so that the derived CLI can offer the choices and
/// reject a typo before a call is made.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PseudoLanguage {
    #[default]
    C,
    Rust,
    ObjectiveC,
}

impl PseudoLanguage {
    fn as_bn(self) -> &'static str {
        match self {
            Self::C => "Pseudo C",
            Self::Rust => "Pseudo Rust",
            Self::ObjectiveC => "Pseudo Objective-C",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFunctionsArgs {
    /// Index of the first function to return, in address order. Defaults to 0.
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    /// Maximum functions to return. Defaults to 100.
    #[schemars(range(min = 1, max = 10000))]
    pub limit: Option<i64>,
    /// Case-insensitive substring the function name must contain.
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListStringsArgs {
    /// Index of the first string to return, in address order. Defaults to 0.
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    /// Maximum strings to return. Defaults to 100.
    #[schemars(range(min = 1, max = 10000))]
    pub limit: Option<i64>,
    /// Case-insensitive substring the decoded content must contain.
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagedTargetArgs {
    /// A function name, or an address: `main`, `0x401000` or `4198400`.
    pub target: String,
    /// Index of the first item to return. Defaults to 0.
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    /// Maximum items to return. Defaults to 100.
    #[schemars(range(min = 1, max = 10000))]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisasmArgs {
    /// A function name, or any address inside the function: `main`, `0x401000`
    /// or `4198400`. An address that falls in the middle of a function resolves
    /// to that function.
    pub target: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PseudoCArgs {
    /// A function name, or any address inside the function: `main`, `0x401000`
    /// or `4198400`. An address that falls in the middle of a function resolves
    /// to that function.
    pub target: String,
    /// Pseudocode dialect. Defaults to C.
    pub language: Option<PseudoLanguage>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameArgs {
    /// The function to rename: a name, or any address inside it.
    pub target: String,
    /// The new name. Applied as a *user* symbol, so later analysis will not
    /// overwrite it.
    pub new_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListSymbolsArgs {
    /// Index of the first symbol to return, in address order. Defaults to 0.
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    /// Maximum symbols to return. Defaults to 100.
    #[schemars(range(min = 1, max = 10000))]
    pub limit: Option<i64>,
    /// Case-insensitive substring the symbol name must contain.
    pub filter: Option<String>,
    /// Restrict to one `SymbolType`. Omit for every symbol.
    ///
    /// `function` on a binary with no imports is the export set; the import
    /// side has its own tool because it spans four types at once.
    pub kind: Option<responses::SymbolKind>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListDataVarsArgs {
    /// Index of the first data variable to return, in address order. Defaults to 0.
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    /// Maximum data variables to return. Defaults to 100.
    #[schemars(range(min = 1, max = 10000))]
    pub limit: Option<i64>,
    /// Case-insensitive substring the name or the type must contain.
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchArgs {
    /// What to look for. A hex byte pattern by default.
    pub query: String,
    /// How to interpret `query`. Defaults to `bytes`.
    pub kind: Option<responses::SearchKind>,
    /// Stop after this many hits. Defaults to 100, capped at 1000.
    #[schemars(range(min = 1, max = 1000))]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemoryReadArgs {
    /// Address to read from: hex (`0x401000`) or decimal. Must start with a digit.
    pub address: String,
    /// Number of bytes to read. Hard cap is 65536.
    #[schemars(range(min = 1, max = 65536))]
    pub length: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommentArgs {
    /// An address, or a name that resolves to that function's start.
    pub target: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetCommentArgs {
    /// An address, or a name that resolves to that function's start.
    pub target: String,
    /// The comment text. Empty string clears.
    pub comment: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeArgs {
    /// The function to analyze: a name, or any address inside it.
    pub target: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisasmRangeArgs {
    /// First address of the range: hex (`0x401000`) or decimal.
    pub start: String,
    /// Length of the range in bytes.
    #[schemars(range(min = 0, max = 4294967295u32))]
    pub length: i64,
    /// Maximum lines to return. Defaults to 200, max 10000.
    #[schemars(range(min = 1, max = 10000))]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ParseDeclarationsArgs {
    /// C declarations to parse (structs, typedefs, prototypes).
    pub source: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TypeQueryArgs {
    /// Type name as stored on the view.
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TypeApplyArgs {
    /// Name to define the type under.
    pub name: String,
    /// One C type declaration (or several; a matching name, else the first, is used).
    pub source: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateDatabaseArgs {
    /// Filesystem path for the `.bndb`.
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TraceDataFlowArgs {
    /// Start address, or a name that resolves to that function's start.
    pub target: String,
    /// Walk direction. Defaults to `forward`.
    pub direction: Option<responses::TraceDirection>,
    /// Maximum BFS depth. Defaults to 5, clamped to `1..=20`.
    #[schemars(range(min = 1, max = 20))]
    pub max_depth: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FunctionCommentArgs {
    /// The function: a name, or any address inside it.
    pub target: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetFunctionCommentArgs {
    /// The function: a name, or any address inside it.
    pub target: String,
    /// The comment text. Empty string clears it.
    pub comment: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameSymbolArgs {
    /// The symbol's address: hex (`0x404020`) or decimal. A name is refused —
    /// renaming by the name you are replacing is ambiguous when two symbols
    /// share it.
    pub address: String,
    /// The new name, applied as a *user* symbol so analysis will not undo it.
    pub new_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListVariablesArgs {
    /// The function: a name, or any address inside it.
    pub target: String,
    /// Index of the first variable to return. Defaults to 0.
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    /// Maximum variables to return. Defaults to 100.
    #[schemars(range(min = 1, max = 10000))]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetVariableArgs {
    /// The function the variable belongs to: a name, or any address inside it.
    pub target: String,
    /// The variable's current name, as `il.pseudo_c` shows it (`var_18`, `rax`).
    pub variable: String,
    /// The new name. Omit to keep the current one.
    pub new_name: Option<String>,
    /// The new type, as a C declaration: `char *`, `struct sockaddr *`,
    /// `uint32_t[8]`. Omit to keep the current one.
    pub new_type: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetPrototypeArgs {
    /// The function: a name, or any address inside it.
    pub target: String,
    /// The full C prototype: `int main(int argc, char **argv)`. The name in the
    /// prototype is ignored — `target` chooses the function.
    pub prototype: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchTargetArgs {
    /// Instruction address: hex (`0x401000`) or decimal.
    pub address: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchApplyArgs {
    /// Instruction address: hex (`0x401000`) or decimal.
    pub address: String,
    /// Value left in the return register. Only read for `skip_and_return`,
    /// where it defaults to 0.
    pub value: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchAssembleArgs {
    /// Address to assemble for and write to.
    pub address: String,
    /// One or more assembly instructions, in this architecture's syntax.
    pub code: String,
    /// Allow the new encoding to be longer than the instruction it replaces,
    /// overwriting whatever follows. Defaults to false.
    pub allow_overwrite: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchBytesArgs {
    /// Address to write to.
    pub address: String,
    /// Hex bytes: `9090`, `90 90`, `90:90`.
    pub bytes: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExportBinaryArgs {
    /// Filesystem path for the patched binary.
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScriptArgs {
    /// The Python source to run. Multi-statement source is fine; it is compiled
    /// as a module, not typed into a REPL.
    pub source: String,
    /// Seconds before the script is interrupted. Defaults to 60, capped at 600.
    #[schemars(range(min = 1, max = 600))]
    pub timeout_secs: Option<i64>,
}

/// Bytes and disassembly for a window starting at `addr`, for a patch's
/// before/after pair.
///
/// Both halves are read the same way over the same width so the two are
/// comparable; a patch that changed the instruction length would otherwise show
/// a difference that is only the window moving.
fn patch_snapshot(
    view: &binaryninja::binary_view::BinaryView,
    addr: u64,
    width: usize,
) -> (String, String) {
    let width = width.clamp(1, 64);
    let bytes = read::bytes_to_hex(&read::read_bytes(view, addr, width));
    // A patch snapshot is a fixed eight-line window on purpose, so being cut off
    // at eight is the intent rather than something to report.
    let listing = crate::bn::disasm::render_range(view, addr, width as u32, 8);
    (bytes, listing.text)
}

/// Run `body` inside one undo transaction, so the whole patch is one entry.
///
/// `patch.revert` reads the top of the undo stack to decide whether it is
/// looking at a patch. Two things make that unreliable without a bracket, both
/// measured: an unbracketed write does not appear on the stack for ~50 ms
/// (`BNCanUndo` answers `false` in that window even though `BNUndo` would
/// work), and a patch that writes twice — `patch.assemble` writes the encoding
/// and then the NOP padding — lands as two entries that undo separately.
fn in_one_undo_entry<T>(
    view: &binaryninja::binary_view::BinaryView,
    body: impl FnOnce(&binaryninja::binary_view::BinaryView) -> Result<T, ToolError>,
) -> Result<T, ToolError> {
    let transaction = bn::patch::begin_undo(view);
    let outcome = body(view);
    // Committed even when the body failed: a failed patch may still have
    // written some of its bytes (`patch::write` says so rather than pretending
    // to roll back), and an entry the caller can revert is better than a
    // transaction left open across the next tool call.
    if let Some(id) = transaction {
        bn::patch::commit_undo(view, &id);
    }
    outcome
}

/// The address out of an undo action summary like
/// `Wrote data of length 0x1 at offset 0x2040`.
///
/// Best effort by design: the summary is Binary Ninja's own prose and could
/// change with a version bump, so a miss returns `None` and the caller still has
/// the summary text itself. Nothing branches on this.
fn offset_in(summary: &str) -> Option<String> {
    let tail = summary.rsplit_once("at offset ")?.1;
    let digits: String = tail
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == 'x' || *c == 'X')
        .collect();
    vibrev_kit::parse_int(digits.trim())
        .ok()
        .map(|value| read::hex(value as u64))
}

/// What a caller has to do for a patch to outlive this process.
const PATCH_PERSISTENCE: &str =
    "In memory only. `database.create_bndb` saves the analysis and the \
patches together; `database.export_binary` writes the patched bytes out as a runnable file. \
Neither happens automatically, and closing the view loses both.";

/// Parse a target that is either an address or a symbol name.
///
/// Returns `(address, name)` with exactly one side populated. Anything starting
/// with a digit is read as a number — `0x` and `0b` included — because a symbol
/// whose name begins with a digit is not legal in any language Binary Ninja
/// demangles.
fn parse_target(target: &str) -> Result<(Option<u64>, Option<String>), ToolError> {
    let t = target.trim();
    if t.is_empty() {
        return Err(ToolError::InvalidParams(
            "target is empty; give a function name or an address".to_owned(),
        ));
    }
    if t.starts_with(|c: char| c.is_ascii_digit()) {
        let value = vibrev_kit::parse_int(t).map_err(ToolError::InvalidParams)?;
        return Ok((Some(value as u64), None));
    }
    Ok((None, Some(t.to_owned())))
}

/// Parse an address string. Unlike [`parse_target`], a name is refused.
fn parse_address(address: &str) -> Result<u64, ToolError> {
    let t = address.trim();
    if t.is_empty() {
        return Err(ToolError::InvalidParams(
            "address is empty; give a hex or decimal address".to_owned(),
        ));
    }
    if !t.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(ToolError::InvalidParams(format!(
            "{t:?} is not an address; give hex (0x401000) or decimal"
        )));
    }
    let value = vibrev_kit::parse_int(t).map_err(ToolError::InvalidParams)?;
    Ok(value as u64)
}

#[vibrev_tool_router(group_about(
    binary = "Segments, sections, functions, strings, imports, data, search",
    il = "Decompile a function to pseudocode",
    disasm = "Linear disassembly of a function or range",
    xref = "Code and data cross-references",
    function = "Callers, callees, basic blocks, and variables",
    annotation = "Comments, names, and user labels",
    memory = "Read bytes from the open view",
    r#type = "Parse, apply and assign C type declarations",
    database = "Create and save .bndb files",
    analyze = "Walk xrefs as a data-flow graph",
    patch = "Modify instructions and bytes in the open view",
    script = "Run Python against this view, in this process"
))]
impl BnMcpServer {
    /// List every memory segment the loader mapped, with permissions.
    ///
    /// Segments are what the file maps into the address space; sections are the
    /// names the format gives to ranges inside them, and `binary.survey` reports
    /// both. Start here when deciding where code lives.
    #[vibrev_tool(
        group = "binary",
        verb = "segments",
        title = "List mapped segments",
        output = "responses::SegmentList",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    pub async fn segments(&self) -> Result<CallToolResponse, ErrorData> {
        let out = self
            .engine
            .read(|view| {
                // Coverage is sampled *before* the data, so a `complete: true`
                // was still true when the data was read.
                let analysis_coverage = bn::coverage(view);
                let segments = read::segments(view);
                Ok(responses::SegmentList {
                    total: segments.len(),
                    segments,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// List every named section the loader described.
    ///
    /// Sections are names the format gives to ranges; segments are the mapped
    /// ranges underneath. `binary.survey` reports both.
    #[vibrev_tool(
        group = "binary",
        verb = "sections",
        title = "List named sections",
        output = "responses::SectionList",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    pub async fn sections(&self) -> Result<CallToolResponse, ErrorData> {
        let out = self
            .engine
            .read(|view| {
                let analysis_coverage = bn::coverage(view);
                let sections = read::sections(view);
                Ok(responses::SectionList {
                    total: sections.len(),
                    sections,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// List functions in address order, one page at a time.
    ///
    /// `total` counts every function matching `filter` across the whole view, not
    /// just this page, so it is safe to page on. `next_offset` is present exactly
    /// when there is more to read and absent — never null — on the last page.
    #[vibrev_tool(
        group = "binary",
        verb = "functions",
        title = "Browse every function",
        output = "responses::FunctionPage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    pub async fn list_functions(
        &self,
        Parameters(args): Parameters<ListFunctionsArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let filter = args.filter.clone();
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let (functions, total) =
                    read::function_page(view, offset, limit, filter.as_deref());
                let page = vibrev_kit::page::Page::counted(functions, offset, total);
                let next_offset = page.next_offset;
                let functions = page.items;
                Ok(responses::FunctionPage {
                    functions,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// List discovered strings, one page at a time.
    ///
    /// Encoding is preserved (`ascii`, `utf8`, `utf16`, `utf32`); displayed
    /// content is capped at 256 characters. `filter` is a case-insensitive
    /// substring of the decoded content.
    #[vibrev_tool(
        group = "binary",
        verb = "strings",
        title = "Browse discovered strings",
        output = "responses::StringPage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    pub async fn list_strings(
        &self,
        Parameters(args): Parameters<ListStringsArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let filter = args.filter.clone();
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let (strings, total) = read::string_page(view, offset, limit, filter.as_deref());
                let page = vibrev_kit::page::Page::counted(strings, offset, total);
                let next_offset = page.next_offset;
                let strings = page.items;
                Ok(responses::StringPage {
                    strings,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// One call's worth of orientation: what the binary is, how big it is, what
    /// it maps, where it starts, its largest functions and its imports bucketed
    /// by a name heuristic.
    ///
    /// The import categories are a substring heuristic, not analysis — treat
    /// them as a reading order, not a finding.
    #[vibrev_tool(
        group = "binary",
        verb = "survey",
        title = "Survey the whole binary",
        output = "responses::Survey",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    pub async fn survey(&self) -> Result<CallToolResponse, ErrorData> {
        let input_path = self.engine.input_path().to_owned();
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let functions = read::summarize_functions(view);
                let imports = read::imported_function_names(view);
                Ok(responses::Survey {
                    metadata: read::metadata(view, &input_path),
                    statistics: read::statistics(view, &functions, imports.len()),
                    segments: read::segments(view),
                    sections: read::sections(view),
                    entry_points: read::entry_point_functions(view),
                    interesting_functions: functions.interesting.clone(),
                    imports_by_category: read::categorize_imports(&imports),
                    limits: responses::SurveyLimits {
                        functions_scanned: functions.scanned,
                        functions_truncated: functions.truncated,
                        max_functions_scanned: read::MAX_SURVEY_FUNCTIONS,
                        interesting_functions_limit: read::INTERESTING_FUNCTIONS,
                    },
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// Decompile one function to pseudocode.
    ///
    /// Goes through the linear view's language representation rather than
    /// walking HLIL, which is what makes this survive the MLIL/HLIL rewrite
    /// upstream issue #7731 describes. Analysis is settled before rendering:
    /// Binary Ninja will otherwise hand back different text for the same
    /// function while it is still refining.
    #[vibrev_tool(
        group = "il",
        verb = "pseudo_c",
        title = "Decompile a function",
        output = "responses::PseudoC",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn pseudo_c(
        &self,
        Parameters(args): Parameters<PseudoCArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let language = args.language.unwrap_or_default();
        let target = args.target.clone();
        let out = self
            .engine
            .read(move |view| {
                let Some(func) = read::resolve_function(view, address, name.as_deref()) else {
                    return Err(ToolError::NotFound(format!(
                        "no function matches {target:?}. Use binary.functions to list what \
                         analysis found."
                    )));
                };
                Ok(responses::PseudoC {
                    c_code: bn::pseudo_c::render(view, &func, language.as_bn()),
                })
            })
            .await;
        finish(out)
    }

    /// Disassemble one function to a linear listing.
    ///
    /// Same cursor as `il.pseudo_c`, but with addresses on. The payload is a
    /// single `listing` field so it pipes as bare text.
    #[vibrev_tool(
        group = "disasm",
        verb = "function",
        title = "Disassemble a function",
        output = "responses::DisasmFunction",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn disasm_function(
        &self,
        Parameters(args): Parameters<DisasmArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let target = args.target.clone();
        let out = self
            .engine
            .read(move |view| {
                let Some(func) = read::resolve_function(view, address, name.as_deref()) else {
                    return Err(ToolError::NotFound(format!(
                        "no function matches {target:?}. Use binary.functions to list what \
                         analysis found."
                    )));
                };
                Ok(responses::DisasmFunction {
                    listing: bn::disasm::render(view, &func),
                })
            })
            .await;
        finish(out)
    }

    /// Code references *to* an address.
    ///
    /// This is address-level: each `from` is a referencing instruction. If
    /// `target` is a name it resolves to that function's start. For calling
    /// *functions*, use `function.callers`.
    #[vibrev_tool(
        group = "xref",
        verb = "code_refs_to",
        title = "Code references to an address",
        output = "responses::CodeRefPage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn code_refs_to(
        &self,
        Parameters(args): Parameters<PagedTargetArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let addr = read::resolve_target_address(view, address, name.as_deref())?;
                let refs = read::code_refs_to(view, addr);
                let page = vibrev_kit::page::Page::of(refs, offset, limit);
                let total = page.total;
                let next_offset = page.next_offset;
                let refs = page.items;
                Ok(responses::CodeRefPage {
                    refs,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// Code references *from* an address.
    ///
    /// This is address-level: each `to` is a destination this instruction
    /// points at. If `target` is a name it resolves to that function's start.
    /// For called *functions*, use `function.callees`.
    #[vibrev_tool(
        group = "xref",
        verb = "code_refs_from",
        title = "Code references from an address",
        output = "responses::CodeRefPage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn code_refs_from(
        &self,
        Parameters(args): Parameters<PagedTargetArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let addr = read::resolve_target_address(view, address, name.as_deref())?;
                let refs = read::code_refs_from(view, addr);
                let page = vibrev_kit::page::Page::of(refs, offset, limit);
                let total = page.total;
                let next_offset = page.next_offset;
                let refs = page.items;
                Ok(responses::CodeRefPage {
                    refs,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// Functions that call this one, one page at a time.
    ///
    /// Deduplicated by function start — each caller appears once, even if it
    /// has several call sites. Distinct from `xref.code_refs_to`, which names
    /// the referencing instruction.
    #[vibrev_tool(
        group = "function",
        verb = "callers",
        title = "List calling functions",
        output = "responses::CallersPage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn function_callers(
        &self,
        Parameters(args): Parameters<PagedTargetArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let target = args.target.clone();
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let Some(func) = read::resolve_function(view, address, name.as_deref()) else {
                    return Err(ToolError::NotFound(format!(
                        "no function matches {target:?}. Use binary.functions to list what \
                         analysis found."
                    )));
                };
                let callers = read::callers(&func);
                let page = vibrev_kit::page::Page::of(callers, offset, limit);
                let total = page.total;
                let next_offset = page.next_offset;
                let callers = page.items;
                Ok(responses::CallersPage {
                    callers,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// Functions this one calls, one page at a time.
    ///
    /// Built from `call_sites` plus code refs, so unresolved indirect jumps
    /// are included as sites and produce no callee when the dest does not
    /// resolve to a function.
    #[vibrev_tool(
        group = "function",
        verb = "callees",
        title = "List called functions",
        output = "responses::CalleesPage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn function_callees(
        &self,
        Parameters(args): Parameters<PagedTargetArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let target = args.target.clone();
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let Some(func) = read::resolve_function(view, address, name.as_deref()) else {
                    return Err(ToolError::NotFound(format!(
                        "no function matches {target:?}. Use binary.functions to list what \
                         analysis found."
                    )));
                };
                let callees = read::callees(view, &func);
                let page = vibrev_kit::page::Page::of(callees, offset, limit);
                let total = page.total;
                let next_offset = page.next_offset;
                let callees = page.items;
                Ok(responses::CalleesPage {
                    callees,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// Rename a function.
    ///
    /// Writes a *user* symbol, which is what makes the name stick: an auto
    /// symbol is analysis output and a later pass may replace it. The change
    /// lives in this view only — nothing here writes to the file on disk.
    #[vibrev_tool(
        group = "annotation",
        verb = "rename_function",
        title = "Rename a function",
        output = "responses::RenameResult",
        annotations(
            read_only = false,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target,new_name")
    )]
    pub async fn rename_function(
        &self,
        Parameters(args): Parameters<RenameArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let new_name = args.new_name.trim().to_owned();
        if new_name.is_empty() {
            return Ok(ToolError::InvalidParams("new_name is empty".to_owned()).to_response());
        }
        let target = args.target.clone();
        let out = self
            .engine
            .write(move |view| {
                let Some(func) = read::resolve_function(view, address, name.as_deref()) else {
                    return Err(ToolError::NotFound(format!(
                        "no function matches {target:?}"
                    )));
                };
                let old_name = read::function_name(&func);
                read::rename_function(view, &func, &new_name).map_err(ToolError::Bn)?;
                Ok(responses::RenameResult {
                    address: read::hex(func.start()),
                    old_name,
                    new_name,
                    ok: true,
                })
            })
            .await;
        finish(out)
    }

    /// Data references *to* an address.
    ///
    /// Address-level: each `from` is a referencing data slot. If `target` is a
    /// name it resolves to that function's start.
    #[vibrev_tool(
        group = "xref",
        verb = "data_refs_to",
        title = "Data references to an address",
        output = "responses::CodeRefPage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn data_refs_to(
        &self,
        Parameters(args): Parameters<PagedTargetArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let addr = read::resolve_target_address(view, address, name.as_deref())?;
                let refs = read::data_refs_to(view, addr);
                let page = vibrev_kit::page::Page::of(refs, offset, limit);
                let total = page.total;
                let next_offset = page.next_offset;
                let refs = page.items;
                Ok(responses::CodeRefPage {
                    refs,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// Data references *from* an address.
    ///
    /// Address-level: each `to` is a destination this address points at. If
    /// `target` is a name it resolves to that function's start.
    #[vibrev_tool(
        group = "xref",
        verb = "data_refs_from",
        title = "Data references from an address",
        output = "responses::CodeRefPage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn data_refs_from(
        &self,
        Parameters(args): Parameters<PagedTargetArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let addr = read::resolve_target_address(view, address, name.as_deref())?;
                let refs = read::data_refs_from(view, addr);
                let page = vibrev_kit::page::Page::of(refs, offset, limit);
                let total = page.total;
                let next_offset = page.next_offset;
                let refs = page.items;
                Ok(responses::CodeRefPage {
                    refs,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// List symbols in address order, one page at a time.
    ///
    /// `filter` is a case-insensitive substring of the symbol name. `total`
    /// counts every match, not just this page.
    #[vibrev_tool(
        group = "binary",
        verb = "symbols",
        title = "Browse every symbol",
        output = "responses::SymbolPage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    pub async fn list_symbols(
        &self,
        Parameters(args): Parameters<ListSymbolsArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let filter = args.filter.clone();
        let kind = args.kind;
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let (symbols, total) =
                    read::symbol_page(view, offset, limit, filter.as_deref(), kind);
                let page = vibrev_kit::page::Page::counted(symbols, offset, total);
                let next_offset = page.next_offset;
                let symbols = page.items;
                Ok(responses::SymbolPage {
                    symbols,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// List imported symbols, one page at a time.
    ///
    /// Covers `ImportedFunction`, `ImportAddress`, `ImportedData` and
    /// `External`, deduplicated by (address, name).
    #[vibrev_tool(
        group = "binary",
        verb = "imports",
        title = "Browse imported symbols",
        output = "responses::ImportPage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    pub async fn list_imports(
        &self,
        Parameters(args): Parameters<ListSymbolsArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let filter = args.filter.clone();
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let (imports, total) = read::import_page(view, offset, limit, filter.as_deref());
                let page = vibrev_kit::page::Page::counted(imports, offset, total);
                let next_offset = page.next_offset;
                let imports = page.items;
                Ok(responses::ImportPage {
                    imports,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// Read bytes from the view.
    ///
    /// Hard cap is 65536 bytes. The `hex` field is lowercase, no spaces. A
    /// short read (unmapped tail) reports the bytes actually returned.
    #[vibrev_tool(
        group = "memory",
        verb = "read",
        title = "Read bytes from memory",
        output = "responses::MemoryRead",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    pub async fn memory_read(
        &self,
        Parameters(args): Parameters<MemoryReadArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let length = match vibrev_kit::parse_unsigned::<usize>(args.length, "length") {
            Ok(length) => length,
            Err(e) => return Ok(ToolError::InvalidParams(e.to_string()).to_response()),
        };
        if length > read::MEMORY_READ_MAX {
            return Ok(ToolError::InvalidParams(format!(
                "length {} exceeds the {}-byte (64 KB) hard cap",
                length,
                read::MEMORY_READ_MAX
            ))
            .to_response());
        }
        let addr = match parse_address(&args.address) {
            Ok(addr) => addr,
            Err(e) => return Ok(e.to_response()),
        };
        let out = self
            .engine
            .read(move |view| {
                let bytes = read::read_bytes(view, addr, length);
                Ok(responses::MemoryRead {
                    address: read::hex(addr),
                    length: bytes.len(),
                    hex: read::bytes_to_hex(&bytes),
                })
            })
            .await;
        finish(out)
    }

    /// Read the global comment at an address.
    ///
    /// A name resolves to that function's start. Empty string when none is set.
    #[vibrev_tool(
        group = "annotation",
        verb = "get_comment",
        title = "Get a comment",
        output = "responses::CommentGet",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn get_comment(
        &self,
        Parameters(args): Parameters<CommentArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let out = self
            .engine
            .read(move |view| {
                let addr = read::resolve_target_address(view, address, name.as_deref())?;
                Ok(responses::CommentGet {
                    address: read::hex(addr),
                    comment: read::comment_at(view, addr),
                })
            })
            .await;
        finish(out)
    }

    /// Set the global comment at an address. Empty string clears.
    ///
    /// A name resolves to that function's start. Lives in this view only —
    /// nothing here writes to the file on disk.
    #[vibrev_tool(
        group = "annotation",
        verb = "set_comment",
        title = "Set a comment",
        output = "responses::CommentSet",
        annotations(
            read_only = false,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target,comment")
    )]
    pub async fn set_comment(
        &self,
        Parameters(args): Parameters<SetCommentArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let comment = args.comment.clone();
        let out = self
            .engine
            .write(move |view| {
                let addr = read::resolve_target_address(view, address, name.as_deref())?;
                read::set_comment_at(view, addr, &comment);
                Ok(responses::CommentSet {
                    address: read::hex(addr),
                    comment,
                    ok: true,
                })
            })
            .await;
        finish(out)
    }

    /// Native basic blocks of a function, one page at a time.
    ///
    /// Each block names its start, end, size and successor starts.
    #[vibrev_tool(
        group = "function",
        verb = "basic_blocks",
        title = "List basic blocks",
        output = "responses::BasicBlockPage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn function_basic_blocks(
        &self,
        Parameters(args): Parameters<PagedTargetArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let target = args.target.clone();
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let Some(func) = read::resolve_function(view, address, name.as_deref()) else {
                    return Err(ToolError::NotFound(format!(
                        "no function matches {target:?}. Use binary.functions to list what \
                         analysis found."
                    )));
                };
                let blocks = read::basic_blocks(&func);
                let page = vibrev_kit::page::Page::of(blocks, offset, limit);
                let total = page.total;
                let next_offset = page.next_offset;
                let blocks = page.items;
                Ok(responses::BasicBlockPage {
                    blocks,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// Orientation dossier for one function: identity, callers, callees, strings.
    ///
    /// No decompile and no listing — those are `il.pseudo_c` and
    /// `disasm.function`. Callers and callees are capped at 50, referenced
    /// strings at 20.
    #[vibrev_tool(
        group = "function",
        verb = "analyze",
        title = "Analyze one function",
        output = "responses::FunctionAnalyze",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn function_analyze(
        &self,
        Parameters(args): Parameters<AnalyzeArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let target = args.target.clone();
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let Some(func) = read::resolve_function(view, address, name.as_deref()) else {
                    return Err(ToolError::NotFound(format!(
                        "no function matches {target:?}. Use binary.functions to list what \
                         analysis found."
                    )));
                };
                Ok(read::analyze_function(view, &func, analysis_coverage))
            })
            .await;
        finish(out)
    }

    /// Disassemble an address range to a linear listing.
    ///
    /// Same cursor as `disasm.function`. The payload is a single `listing`
    /// field so it pipes as bare text.
    #[vibrev_tool(
        group = "disasm",
        verb = "range",
        title = "Disassemble an address range",
        output = "responses::DisasmRange",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "start")
    )]
    pub async fn disasm_range(
        &self,
        Parameters(args): Parameters<DisasmRangeArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let start = match parse_address(&args.start) {
            Ok(addr) => addr,
            Err(e) => return Ok(e.to_response()),
        };
        let length = match vibrev_kit::parse_unsigned::<u32>(args.length, "length") {
            Ok(length) => length,
            Err(e) => return Ok(ToolError::InvalidParams(e.to_string()).to_response()),
        };
        let limit = vibrev_kit::page::capped(args.limit, 200, MAX_LIMIT);
        let out = self
            .engine
            .read(move |view| {
                let listing = bn::disasm::render_range(view, start, length, limit);
                Ok(responses::DisasmRange {
                    listing: listing.text,
                    truncated: listing.truncated,
                })
            })
            .await;
        finish(out)
    }

    /// Parse C type declarations against the view's default platform.
    ///
    /// Does not define anything. Use `type.apply` to write a parsed type onto
    /// the view.
    #[vibrev_tool(
        group = "type",
        verb = "parse_declarations",
        title = "Parse C type declarations",
        output = "responses::TypeParseResult",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "source")
    )]
    pub async fn parse_declarations(
        &self,
        Parameters(args): Parameters<ParseDeclarationsArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let source = args.source.clone();
        let out = self
            .engine
            .read(move |view| read::parse_declarations(view, &source))
            .await;
        finish(out)
    }

    /// Look up a named type on the view.
    #[vibrev_tool(
        group = "type",
        verb = "query",
        title = "Query a named type",
        output = "responses::TypeQuery",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "name")
    )]
    pub async fn type_query(
        &self,
        Parameters(args): Parameters<TypeQueryArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = args.name.trim().to_owned();
        if name.is_empty() {
            return Ok(ToolError::InvalidParams("name is empty".to_owned()).to_response());
        }
        let out = self
            .engine
            .read(move |view| match read::query_type(view, &name) {
                Some(found) => Ok(found),
                None => Err(ToolError::NotFound(format!("no type named {name:?}"))),
            })
            .await;
        finish(out)
    }

    /// Parse a C type and define it as a user type on the view.
    ///
    /// Uses the parsed type whose name matches `name`, or the first parsed
    /// type if none matches.
    #[vibrev_tool(
        group = "type",
        verb = "apply",
        title = "Apply a user type",
        output = "responses::TypeApply",
        annotations(
            read_only = false,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "name,source")
    )]
    pub async fn type_apply(
        &self,
        Parameters(args): Parameters<TypeApplyArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = args.name.trim().to_owned();
        if name.is_empty() {
            return Ok(ToolError::InvalidParams("name is empty".to_owned()).to_response());
        }
        let source = args.source.clone();
        let out = self
            .engine
            .write(move |view| read::apply_type(view, &name, &source))
            .await;
        finish(out)
    }

    /// Create a `.bndb` at `path`.
    ///
    /// Writes a new file; does not overwrite the process's open view. A later
    /// `session.open` of that path loads the saved analysis.
    #[vibrev_tool(
        group = "database",
        verb = "create_bndb",
        title = "Create a .bndb database",
        output = "responses::CreateDatabase",
        annotations(
            read_only = false,
            destructive = false,
            idempotent = false,
            open_world = false
        ),
        cli(positional = "path")
    )]
    pub async fn create_bndb(
        &self,
        Parameters(args): Parameters<CreateDatabaseArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let path = args.path.trim().to_owned();
        if path.is_empty() {
            return Ok(ToolError::InvalidParams("path is empty".to_owned()).to_response());
        }
        let out = self
            .engine
            .write(move |view| {
                let created = read::create_database(view, &path);
                if !created {
                    return Err(ToolError::Bn(format!(
                        "Binary Ninja refused to create a database at {path}"
                    )));
                }
                Ok(responses::CreateDatabase {
                    path,
                    created: true,
                    message: "Database created.".to_owned(),
                })
            })
            .await;
        finish(out)
    }

    /// Save the current view.
    ///
    /// Succeeds only when the view is already a database. Use
    /// `database.create_bndb` to write a new `.bndb` first.
    #[vibrev_tool(
        group = "database",
        verb = "save",
        title = "Save the current database",
        output = "responses::SaveDatabase",
        annotations(
            read_only = false,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    pub async fn database_save(&self) -> Result<CallToolResponse, ErrorData> {
        let out = self
            .engine
            .write(|view| {
                let saved = read::save_view(view);
                let message = if saved {
                    "View saved.".to_owned()
                } else if !read::is_database_backed(view) {
                    "Save failed: this view is not a database. Use database.create_bndb first."
                        .to_owned()
                } else {
                    "Binary Ninja refused to save the view.".to_owned()
                };
                Ok(responses::SaveDatabase { saved, message })
            })
            .await;
        finish(out)
    }

    /// Walk xrefs forward or backward from one address, by BFS.
    ///
    /// Not a call graph: each hop is a code or data reference. Hard caps are
    /// 200 nodes and 500 edges; `max_depth` defaults to 5 and is clamped to
    /// `1..=20`.
    #[vibrev_tool(
        group = "analyze",
        verb = "trace_data_flow",
        title = "Trace data flow over xrefs",
        output = "responses::TraceDataFlow",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn trace_data_flow(
        &self,
        Parameters(args): Parameters<TraceDataFlowArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let direction = args.direction.unwrap_or_default();
        let max_depth = vibrev_kit::page::capped(
            args.max_depth,
            read::TRACE_DEFAULT_DEPTH,
            read::TRACE_MAX_DEPTH,
        );
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let start = read::resolve_target_address(view, address, name.as_deref())?;
                Ok(read::trace_data_flow(
                    view,
                    start,
                    direction,
                    max_depth,
                    analysis_coverage,
                ))
            })
            .await;
        finish(out)
    }

    /// List the data variables Binary Ninja recovered.
    ///
    /// `binary.symbols` gives a name without a type and `xref.data_refs_to`
    /// gives an address without either; this is the tool that says what lives at
    /// an address and how wide it is. A global table is usually the way into a
    /// driver or a firmware image.
    ///
    /// `filter` matches the name *or* the type, so `filter: "char"` finds the
    /// string tables and `filter: "handler"` finds the ones named for what they
    /// hold.
    #[vibrev_tool(
        group = "binary",
        verb = "data_vars",
        title = "Browse data variables",
        output = "responses::DataVarPage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    pub async fn list_data_vars(
        &self,
        Parameters(args): Parameters<ListDataVarsArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let filter = args.filter.clone();
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let (data_vars, total) =
                    read::data_var_page(view, offset, limit, filter.as_deref());
                let page = vibrev_kit::page::Page::counted(data_vars, offset, total);
                let next_offset = page.next_offset;
                let data_vars = page.items;
                Ok(responses::DataVarPage {
                    data_vars,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// Search the whole view for bytes, disassembly text, or a constant.
    ///
    /// Three questions that share a scan, so they share a tool and differ by
    /// `kind`:
    ///
    /// * `bytes` — a hex pattern (`4889e5`, `48 89 e5`). The first thing to
    ///   reach for in a stripped binary.
    /// * `text` — a substring of the rendered disassembly, so `"call"` or a
    ///   register name.
    /// * `constant` — an integer as it appears in an instruction, hex or
    ///   decimal.
    ///
    /// Overlapping matches are all reported: the scan resumes one *byte* past a
    /// hit, not one match. `truncated` says the limit stopped it, in which case
    /// the hit count is a floor.
    #[vibrev_tool(
        group = "binary",
        verb = "search",
        title = "Search bytes, text or constants",
        output = "responses::SearchResult",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "query")
    )]
    pub async fn search(
        &self,
        Parameters(args): Parameters<SearchArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let kind = args.kind.unwrap_or_default();
        let limit = vibrev_kit::page::capped(args.limit, DEFAULT_LIMIT, 1_000);
        let query = args.query.clone();
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                read::search(view, kind, &query, limit, analysis_coverage)
            })
            .await;
        finish(out)
    }

    /// Read the comment attached to a function.
    ///
    /// Not the same object as `annotation.get_comment`, which reads the note at
    /// one *address*. Binary Ninja keeps both, and a summary written on the
    /// function is where a reader looks for it.
    #[vibrev_tool(
        group = "annotation",
        verb = "get_function_comment",
        title = "Read a function's comment",
        output = "responses::FunctionCommentGet",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn get_function_comment(
        &self,
        Parameters(args): Parameters<FunctionCommentArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let target = args.target.clone();
        let out = self
            .engine
            .read(move |view| {
                let Some(func) = read::resolve_function(view, address, name.as_deref()) else {
                    return Err(ToolError::NotFound(format!(
                        "no function matches {target:?}"
                    )));
                };
                Ok(responses::FunctionCommentGet {
                    address: read::hex(func.start()),
                    name: read::function_name(&func),
                    comment: read::function_comment(&func),
                })
            })
            .await;
        finish(out)
    }

    /// Attach a comment to a function.
    ///
    /// This is the note on the function itself; `annotation.set_comment` writes
    /// at an address instead. An empty string clears it.
    #[vibrev_tool(
        group = "annotation",
        verb = "set_function_comment",
        title = "Comment a function",
        output = "responses::FunctionCommentSet",
        annotations(
            read_only = false,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target,comment")
    )]
    pub async fn set_function_comment(
        &self,
        Parameters(args): Parameters<SetFunctionCommentArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let target = args.target.clone();
        let comment = args.comment.clone();
        let out = self
            .engine
            .write(move |view| {
                let Some(func) = read::resolve_function(view, address, name.as_deref()) else {
                    return Err(ToolError::NotFound(format!(
                        "no function matches {target:?}"
                    )));
                };
                read::set_function_comment(&func, &comment);
                Ok(responses::FunctionCommentSet {
                    address: read::hex(func.start()),
                    name: read::function_name(&func),
                    comment: read::function_comment(&func),
                    ok: true,
                })
            })
            .await;
        finish(out)
    }

    /// Rename the symbol at an address — a data variable, an import thunk, a
    /// label.
    ///
    /// Use `annotation.rename_function` for a function: it resolves a name or an
    /// address anywhere inside the body, while this one needs the symbol's exact
    /// address. Applied as a *user* symbol, so analysis will not overwrite it.
    #[vibrev_tool(
        group = "annotation",
        verb = "rename_symbol",
        title = "Rename a symbol",
        output = "responses::SymbolRename",
        annotations(
            read_only = false,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address,new_name")
    )]
    pub async fn rename_symbol(
        &self,
        Parameters(args): Parameters<RenameSymbolArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let address = match parse_address(&args.address) {
            Ok(addr) => addr,
            Err(e) => return Ok(e.to_response()),
        };
        let new_name = args.new_name.trim().to_owned();
        if new_name.is_empty() {
            return Ok(ToolError::InvalidParams("new_name is empty".to_owned()).to_response());
        }
        let out = self
            .engine
            .write(move |view| read::rename_symbol(view, address, &new_name))
            .await;
        finish(out)
    }

    /// List the variables Binary Ninja recovered for a function.
    ///
    /// These are the names `il.pseudo_c` prints — `var_18`, `arg1`, `rax` — and
    /// the types it renders them with. This is the tool to call before
    /// `function.set_variable`, because that one addresses a variable by the
    /// name shown here.
    #[vibrev_tool(
        group = "function",
        verb = "variables",
        title = "List a function's variables",
        output = "responses::VariablePage",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target")
    )]
    pub async fn list_variables(
        &self,
        Parameters(args): Parameters<ListVariablesArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let (offset, limit) = match page(args.offset, args.limit) {
            Ok(page) => page,
            Err(e) => return Ok(e.to_response()),
        };
        let target = args.target.clone();
        let out = self
            .engine
            .read(move |view| {
                let analysis_coverage = bn::coverage(view);
                let Some(func) = read::resolve_function(view, address, name.as_deref()) else {
                    return Err(ToolError::NotFound(format!(
                        "no function matches {target:?}"
                    )));
                };
                let all = read::variables(&func);
                let page = vibrev_kit::page::Page::of(all, offset, limit);
                let total = page.total;
                let next_offset = page.next_offset;
                let variables = page.items;
                Ok(responses::VariablePage {
                    address: read::hex(func.start()),
                    name: read::function_name(&func),
                    variables,
                    total,
                    offset,
                    limit,
                    next_offset,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// Rename a variable, retype it, or both.
    ///
    /// Retyping is the one lever this tool surface has on pseudocode quality:
    /// naming a `void *` as `struct sockaddr *` changes what `il.pseudo_c`
    /// renders at every use, not just at the declaration. Both sides are written
    /// together — the one you omit is re-supplied from what the variable already
    /// has, so a rename never silently resets the type.
    ///
    /// The variable is addressed by the name `function.variables` reports, which
    /// is also the name pseudocode prints.
    #[vibrev_tool(
        group = "function",
        verb = "set_variable",
        title = "Rename or retype a variable",
        output = "responses::VariableSet",
        annotations(
            read_only = false,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target,variable")
    )]
    pub async fn set_variable(
        &self,
        Parameters(args): Parameters<SetVariableArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        if args.new_name.is_none() && args.new_type.is_none() {
            return Ok(ToolError::InvalidParams(
                "give new_name, new_type, or both; neither was set".to_owned(),
            )
            .to_response());
        }
        let target = args.target.clone();
        let variable = args.variable.clone();
        let new_name = args.new_name.clone();
        let new_type = args.new_type.clone();
        let out = self
            .engine
            .write(move |view| {
                let Some(func) = read::resolve_function(view, address, name.as_deref()) else {
                    return Err(ToolError::NotFound(format!(
                        "no function matches {target:?}"
                    )));
                };
                read::set_variable(
                    view,
                    &func,
                    &variable,
                    new_name.as_deref(),
                    new_type.as_deref(),
                )
            })
            .await;
        finish(out)
    }

    /// Give a function a prototype, as a C declaration.
    ///
    /// `type.parse_declarations` and `type.apply` put a type *on the view*;
    /// this is what puts one *on a function*, and it is what makes
    /// `il.pseudo_c` show real arguments instead of recovered guesses. Analysis
    /// is re-run before the new signature is read back, so the returned `after`
    /// is what Binary Ninja settled on rather than what was asked for.
    #[vibrev_tool(
        group = "type",
        verb = "set_function_prototype",
        title = "Set a function's prototype",
        output = "responses::FunctionPrototype",
        annotations(
            read_only = false,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "target,prototype")
    )]
    pub async fn set_function_prototype(
        &self,
        Parameters(args): Parameters<SetPrototypeArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (address, name) = match parse_target(&args.target) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(e.to_response()),
        };
        let prototype = args.prototype.clone();
        let target = args.target.clone();
        let out = self
            .engine
            .write(move |view| {
                let Some(func) = read::resolve_function(view, address, name.as_deref()) else {
                    return Err(ToolError::NotFound(format!(
                        "no function matches {target:?}"
                    )));
                };
                read::set_function_prototype(view, &func, &prototype)
            })
            .await;
        finish(out)
    }

    /// Ask what can be patched at an address before trying it.
    ///
    /// Binary Ninja refuses an inapplicable patch by writing nothing and
    /// returning false, which is indistinguishable from a no-op unless you asked
    /// first. This reports the instruction's current bytes and listing alongside
    /// the five answers, so one call is enough to decide.
    ///
    /// `can_nop` and `can_never_branch` are different questions. Any instruction
    /// can be NOPed; `can_never_branch` says this one is a branch, so NOPing it
    /// specifically means "never taken". `patch.nop` is the tool for both.
    #[vibrev_tool(
        group = "patch",
        verb = "available",
        title = "What can be patched here",
        output = "responses::PatchAvailability",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    pub async fn patch_available(
        &self,
        Parameters(args): Parameters<PatchTargetArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let address = match parse_address(&args.address) {
            Ok(addr) => addr,
            Err(e) => return Ok(e.to_response()),
        };
        let out = self
            .engine
            .read(move |view| {
                let availability = bn::patch::availability(view, address)?;
                let width = availability.instruction_length.max(1);
                let (bytes, listing) = patch_snapshot(view, address, width);
                Ok(responses::PatchAvailability {
                    address: read::hex(address),
                    function: read::function_name_at_address(view, address),
                    instruction_length: availability.instruction_length,
                    bytes,
                    listing,
                    can_nop: availability.can_nop,
                    can_never_branch: availability.can_never_branch,
                    can_always_branch: availability.can_always_branch,
                    can_invert_branch: availability.can_invert_branch,
                    can_skip_and_return: availability.can_skip_and_return,
                    can_assemble: availability.can_assemble,
                })
            })
            .await;
        finish(out)
    }

    /// Replace the instruction at an address with NOPs.
    ///
    /// This is also what "never branch" means — making a conditional jump never
    /// taken is NOPing it, and `BNConvertToNop` is the single core call behind
    /// both names. Binary Ninja chooses the padding, so the instruction's whole
    /// length is covered.
    #[vibrev_tool(
        group = "patch",
        verb = "nop",
        title = "NOP out an instruction",
        output = "responses::PatchResult",
        annotations(
            read_only = false,
            destructive = true,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    pub async fn patch_nop(
        &self,
        Parameters(args): Parameters<PatchTargetArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.structured_patch(&args.address, responses::PatchOperation::Nop, None)
            .await
    }

    /// Make a conditional branch always taken.
    #[vibrev_tool(
        group = "patch",
        verb = "always_branch",
        title = "Force a branch taken",
        output = "responses::PatchResult",
        annotations(
            read_only = false,
            destructive = true,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    pub async fn patch_always_branch(
        &self,
        Parameters(args): Parameters<PatchTargetArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.structured_patch(&args.address, responses::PatchOperation::AlwaysBranch, None)
            .await
    }

    /// Flip a conditional branch's sense.
    #[vibrev_tool(
        group = "patch",
        verb = "invert_branch",
        title = "Invert a branch condition",
        output = "responses::PatchResult",
        annotations(
            read_only = false,
            destructive = true,
            // Inverting twice returns the original, so this is its own inverse
            // rather than idempotent. Calling it again does not leave the view
            // where the first call did.
            idempotent = false,
            open_world = false
        ),
        cli(positional = "address")
    )]
    pub async fn patch_invert_branch(
        &self,
        Parameters(args): Parameters<PatchTargetArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.structured_patch(&args.address, responses::PatchOperation::InvertBranch, None)
            .await
    }

    /// Skip a call and leave `value` in the return register.
    ///
    /// The usual shape is neutering a check: `skip_and_return` on the call to it
    /// with the value that means "passed". `value` defaults to 0.
    #[vibrev_tool(
        group = "patch",
        verb = "skip_and_return",
        title = "Skip a call, return a value",
        output = "responses::PatchResult",
        annotations(
            read_only = false,
            destructive = true,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    pub async fn patch_skip_and_return(
        &self,
        Parameters(args): Parameters<PatchApplyArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let value = match args.value.as_deref() {
            Some(text) => match vibrev_kit::parse_int(text.trim()) {
                Ok(v) => Some(v as u64),
                Err(e) => {
                    return Ok(ToolError::InvalidParams(format!(
                        "value {text:?} is not an integer: {e}"
                    ))
                    .to_response())
                }
            },
            None => None,
        };
        self.structured_patch(
            &args.address,
            responses::PatchOperation::SkipAndReturn,
            value,
        )
        .await
    }

    /// Assemble instructions and write them at an address.
    ///
    /// Three things happen that a caller should not have to arrange.
    ///
    /// The assembler's own error text comes back verbatim on a failure, because
    /// "invalid operand" from the assembler says more than this layer could.
    ///
    /// A **shorter** encoding is padded with NOPs out to the end of the
    /// instruction it replaced, so the tail does not decode as garbage.
    /// `padding_bytes` reports how many. When the architecture's NOP is not one
    /// byte, the padding is skipped and `note` says so rather than guessing.
    ///
    /// A **longer** encoding is refused unless `allow_overwrite` is set, and the
    /// refusal says exactly how many bytes it would have run past the end.
    #[vibrev_tool(
        group = "patch",
        verb = "assemble",
        title = "Assemble and write",
        output = "responses::PatchResult",
        annotations(
            read_only = false,
            destructive = true,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address,code")
    )]
    pub async fn patch_assemble(
        &self,
        Parameters(args): Parameters<PatchAssembleArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let address = match parse_address(&args.address) {
            Ok(addr) => addr,
            Err(e) => return Ok(e.to_response()),
        };
        if args.code.trim().is_empty() {
            return Ok(ToolError::InvalidParams("code is empty".to_owned()).to_response());
        }
        let code = args.code.clone();
        let allow_overwrite = args.allow_overwrite.unwrap_or(false);
        let out = self
            .engine
            .write(move |view| {
                in_one_undo_entry(view, |view| {
                    let original_length = bn::patch::instruction_length(view, address);
                    let assembled = bn::patch::assemble(view, address, &code)?;

                    let mut note = None;
                    let mut padding = 0usize;
                    let mut to_write = assembled.clone();
                    if original_length > 0 && assembled.len() > original_length && !allow_overwrite
                    {
                        return Err(ToolError::InvalidParams(format!(
                            "{code:?} assembles to {} bytes but the instruction at {} is {} — it \
                         would run {} bytes into whatever follows. Pass allow_overwrite to do \
                         it anyway.",
                            assembled.len(),
                            read::hex(address),
                            original_length,
                            assembled.len() - original_length
                        )));
                    }
                    if original_length > assembled.len() {
                        match bn::patch::nop_byte(view, address) {
                            Some(nop) => {
                                padding = original_length - assembled.len();
                                to_write.extend(std::iter::repeat_n(nop, padding));
                            }
                            None => {
                                note = Some(format!(
                                    "The new encoding is {} bytes shorter than the instruction it \
                                 replaced, and this architecture has no single-byte NOP to pad \
                                 with. The trailing {} bytes are still the old instruction's \
                                 and will decode as something else.",
                                    original_length - assembled.len(),
                                    original_length - assembled.len()
                                ));
                            }
                        }
                    }

                    let width = original_length.max(to_write.len());
                    let (bytes_before, listing_before) = patch_snapshot(view, address, width);
                    let written = bn::patch::write(view, address, &to_write)?;
                    view.update_analysis_and_wait();
                    let (bytes_after, listing_after) = patch_snapshot(view, address, width);

                    Ok(responses::PatchResult {
                        address: read::hex(address),
                        operation: "assemble".to_owned(),
                        bytes_before,
                        bytes_after,
                        listing_before,
                        listing_after,
                        bytes_written: written,
                        padding_bytes: padding,
                        ok: true,
                        note,
                        persistence: PATCH_PERSISTENCE.to_owned(),
                    })
                })
            })
            .await;
        finish(out)
    }

    /// Write raw bytes at an address.
    ///
    /// The escape hatch under `patch.assemble`: an encoding the assembler will
    /// not produce, or data rather than code. Nothing is checked against
    /// instruction boundaries, so this is the one patch tool that will happily
    /// leave a half-instruction behind — `patch.available` first if that matters.
    ///
    /// A short write is an error, not a partial success: the view refusing to
    /// take all of it usually means the range runs off the end of a segment.
    #[vibrev_tool(
        group = "patch",
        verb = "bytes",
        title = "Write raw bytes",
        output = "responses::PatchResult",
        annotations(
            read_only = false,
            destructive = true,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address,bytes")
    )]
    pub async fn patch_bytes(
        &self,
        Parameters(args): Parameters<PatchBytesArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let address = match parse_address(&args.address) {
            Ok(addr) => addr,
            Err(e) => return Ok(e.to_response()),
        };
        let bytes = match read::parse_hex_bytes(&args.bytes) {
            Ok(bytes) => bytes,
            Err(e) => return Ok(e.to_response()),
        };
        let out = self
            .engine
            .write(move |view| {
                in_one_undo_entry(view, |view| {
                    let width = bn::patch::instruction_length(view, address).max(bytes.len());
                    let (bytes_before, listing_before) = patch_snapshot(view, address, width);
                    let written = bn::patch::write(view, address, &bytes)?;
                    view.update_analysis_and_wait();
                    let (bytes_after, listing_after) = patch_snapshot(view, address, width);
                    Ok(responses::PatchResult {
                        address: read::hex(address),
                        operation: "bytes".to_owned(),
                        bytes_before,
                        bytes_after,
                        listing_before,
                        listing_after,
                        bytes_written: written,
                        padding_bytes: 0,
                        ok: true,
                        note: None,
                        persistence: PATCH_PERSISTENCE.to_owned(),
                    })
                })
            })
            .await;
        finish(out)
    }

    /// Undo the most recent patch.
    ///
    /// Binary Ninja's undo stack is per-file and strictly last-in-first-out, and
    /// it holds every edit — a rename, a comment and a patch all land on it. So
    /// this tool looks before it acts: it reads the top entry, and reverts it
    /// **only if every action in it is a write to the view's data**. If the top
    /// entry is something else, nothing is undone and the response names what is
    /// there, because undoing a rename in answer to "revert my patch" is worse
    /// than refusing.
    ///
    /// That also means the order matters. Patch, then rename, then call this,
    /// and it will decline — the rename is on top. Revert the rename yourself,
    /// or accept that the patch is now history you have to overwrite rather than
    /// undo. There is no targeted revert: Binary Ninja's
    /// `RevertUndoActions(id)` looks like one, but [measured] it is a silent
    /// no-op on any transaction that already has a newer one above it.
    ///
    /// Each patch tool writes exactly one undo entry, including
    /// `patch.assemble`'s encoding-plus-padding, so one call here takes back one
    /// patch.
    #[vibrev_tool(
        group = "patch",
        verb = "revert",
        title = "Undo the last patch",
        output = "responses::PatchRevert",
        annotations(
            read_only = false,
            destructive = true,
            // Calling it twice takes back two patches, not one twice.
            idempotent = false,
            open_world = false
        )
    )]
    pub async fn patch_revert(&self) -> Result<CallToolResponse, ErrorData> {
        let out = self
            .engine
            .write(move |view| {
                let mut entries = bn::patch::undo_entries(view);
                let Some(top) = entries.pop() else {
                    return Err(ToolError::NotFound(
                        "there is nothing on the undo stack; no patch has been applied to                          this view in this session"
                            .to_owned(),
                    ));
                };
                if !top.is_only_data_writes() {
                    return Err(ToolError::InvalidParams(format!(
                        "the newest change is not a patch, so reverting would take back                          something else. Binary Ninja describes it as: {}. Undo is                          last-in-first-out and there is no way to target an older entry.",
                        if top.actions.is_empty() {
                            "an entry with no described actions".to_owned()
                        } else {
                            top.actions.join("; ")
                        }
                    )));
                }

                let reverted = top.actions.clone();
                if !bn::patch::undo(view) {
                    return Err(ToolError::Bn(
                        "Binary Ninja refused the undo even though the stack was not empty"
                            .to_owned(),
                    ));
                }
                view.update_analysis_and_wait();

                // Recount after the undo rather than subtracting one: an undo
                // can be refused, and reporting a number derived from what we
                // expected would hide that.
                let after = bn::patch::undo_entries(view);
                let reverts_remaining = after
                    .iter()
                    .rev()
                    .take_while(|entry| entry.is_only_data_writes())
                    .count();
                let next = after.last().map(|entry| entry.actions.join("; "));

                Ok(responses::PatchRevert {
                    ok: true,
                    addresses: reverted.iter().filter_map(|a| offset_in(a)).collect(),
                    reverted,
                    next,
                    reverts_remaining,
                    message: "The patch is undone in memory. Nothing was written to disk                               either way."
                        .to_owned(),
                })
            })
            .await;
        finish(out)
    }

    /// Write the patched binary out as a file.
    ///
    /// Not a `.bndb` — this is the input format with every patch applied, which
    /// is the artifact you actually run. `database.create_bndb` is the other
    /// half: it saves the analysis, the names and the comments, and reopening it
    /// brings the patches back too.
    ///
    /// The file is written fresh; the view keeps pointing at what it was loaded
    /// from.
    #[vibrev_tool(
        group = "database",
        verb = "export_binary",
        title = "Write the patched binary",
        output = "responses::ExportBinary",
        annotations(
            read_only = false,
            destructive = false,
            idempotent = true,
            open_world = true
        ),
        cli(positional = "path")
    )]
    pub async fn export_binary(
        &self,
        Parameters(args): Parameters<ExportBinaryArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let path = args.path.trim().to_owned();
        if path.is_empty() {
            return Ok(ToolError::InvalidParams("path is empty".to_owned()).to_response());
        }
        let out = self
            .engine
            .write(move |view| {
                let written = bn::patch::export_binary(view, &path)?;
                Ok(responses::ExportBinary {
                    path: path.clone(),
                    written,
                    message: if written {
                        format!("Wrote the patched binary to {path}.")
                    } else {
                        format!(
                            "Binary Ninja declined to write {path}. The view type has to support \
                             saving, and the path has to be writable."
                        )
                    },
                })
            })
            .await;
        finish(out)
    }

    /// Run Python against this view, using Binary Ninja's own Python API.
    ///
    /// The script runs **in this process**, against the analysis this worker has
    /// already paid for, so `bv` is bound to the open `BinaryView` and there is
    /// nothing to load. Writes are visible to the other tools as soon as the
    /// script returns.
    ///
    /// Return a value by assigning to a variable named `result`; it comes back
    /// as JSON when it is serializable and as `repr()` when it is not.
    /// `print()` is captured into `stdout` rather than interleaved with it.
    ///
    /// The interpreter is one long-lived console, so names defined by one call
    /// are still there in the next — use `script.reset` to start clean.
    ///
    /// Two limits worth knowing before writing the script. **This process speaks
    /// MCP over its real stdout**, so `print()` is safe but `os.write(1, ...)`
    /// and `sys.__stdout__` corrupt the session. And a script that outlives
    /// `timeout_secs` is interrupted with `KeyboardInterrupt`, which Python
    /// delivers between bytecodes — a call blocked inside Binary Ninja's core
    /// will not notice it until that call returns.
    #[vibrev_tool(
        group = "script",
        verb = "python",
        title = "Run a Python script",
        output = "responses::ScriptRun",
        annotations(
            // Everything a script may do, declared at its widest: it can rename,
            // retype, write files and open sockets. Anything narrower would be a
            // claim this tool cannot keep.
            read_only = false,
            destructive = true,
            idempotent = false,
            open_world = true
        ),
        cli(positional = "source")
    )]
    pub async fn script_python(
        &self,
        Parameters(args): Parameters<ScriptArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        if args.source.trim().is_empty() {
            return Ok(ToolError::InvalidParams("source is empty".to_owned()).to_response());
        }
        // Clamped rather than refused, like a page size and for the same reason
        // (see `page`); the clamp is also what makes the cast total.
        let timeout = std::time::Duration::from_secs(
            args.timeout_secs
                .unwrap_or(bn::script::DEFAULT_TIMEOUT_SECS)
                .clamp(1, bn::script::MAX_TIMEOUT_SECS) as u64,
        );
        let source = args.source.clone();
        let out = self
            .engine
            .script(move |view, console| {
                // Sampled before the run, like every other aggregate: a script
                // that counts functions on an unconverged view is wrong in the
                // same way a list tool would be.
                let analysis_coverage = bn::coverage(view);
                let run = console.run(&source, timeout);
                Ok(responses::ScriptRun {
                    ok: run.ok,
                    stdout: run.stdout,
                    result: run.result,
                    error: run.error,
                    truncated: run.truncated,
                    timed_out: run.timed_out,
                    elapsed_secs: run.elapsed_secs,
                    analysis_coverage,
                })
            })
            .await;
        finish(out)
    }

    /// Forget every name the previous scripts defined.
    ///
    /// The console is one interpreter for the life of the process, which is what
    /// lets a script build on the last one — and also what lets a stale variable
    /// be mistaken for a fresh answer. This clears the namespace without
    /// restarting the interpreter, so `bv` and the Binary Ninja bindings stay
    /// bound.
    #[vibrev_tool(
        group = "script",
        verb = "reset",
        title = "Clear the Python namespace",
        output = "responses::ScriptReset",
        annotations(
            read_only = false,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    pub async fn script_reset(&self) -> Result<CallToolResponse, ErrorData> {
        let out = self
            .engine
            .script(move |_view, console| {
                console.reset()?;
                Ok(responses::ScriptReset {
                    ok: true,
                    message: "The Python namespace is empty again; `bv` is still bound.".to_owned(),
                })
            })
            .await;
        finish(out)
    }
}

#[tool_handler(router = Self::tool_router())]
impl ServerHandler for BnMcpServer {
    fn get_info(&self) -> ServerInfo {
        // `engine_identity!()` rather than `Implementation::from_build_env()`:
        // the latter expands `env!("CARGO_PKG_NAME")` inside rmcp's crate, so a
        // server that uses it reports its own name as `rmcp`.
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(vibrev_kit::engine_identity!())
            .with_instructions(
                "Binary Ninja worker. This process holds exactly one BinaryView and every \
                 tool reads it. Analysis is settled before any answer is produced, and tools \
                 reporting totals or full lists carry `analysis_coverage` saying so.",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_that_starts_with_a_digit_is_an_address_in_any_base() {
        assert_eq!(parse_target("0x401000").unwrap().0, Some(0x401000));
        assert_eq!(parse_target("4198400").unwrap().0, Some(4198400));
        assert_eq!(parse_target("0b1011").unwrap().0, Some(11));
    }

    #[test]
    fn a_target_that_starts_with_a_letter_is_a_name() {
        let (addr, name) = parse_target("main").unwrap();
        assert_eq!(addr, None);
        assert_eq!(name.as_deref(), Some("main"));
        // Leading/trailing space is the shape a shell pipeline produces, and
        // treating it as part of a symbol name would only ever fail to match.
        assert_eq!(
            parse_target("  sub_1000 ").unwrap().1.as_deref(),
            Some("sub_1000")
        );
    }

    #[test]
    fn an_empty_target_is_refused_rather_than_read_as_address_zero() {
        assert!(parse_target("   ").is_err());
    }

    /// The two halves of `page`, which are deliberately not symmetric: an
    /// unreasonable page size is served as the largest reasonable one, and a
    /// negative offset is an error rather than an empty page.
    #[test]
    fn a_page_size_is_clamped_and_a_negative_offset_is_refused() {
        assert_eq!(page(None, None).expect("defaults"), (0, 100));
        assert_eq!(page(Some(40), Some(1_000_000)).expect("huge"), (40, 10_000));
        assert_eq!(page(None, Some(0)).expect("zero"), (0, 1));

        let refused = page(Some(-5), None).expect_err("a negative offset");
        assert!(
            matches!(refused, ToolError::InvalidParams(_)),
            "{refused:?}"
        );
        // The empty page an unchecked cast would answer with instead.
        assert_eq!(-5i64 as usize, usize::MAX - 4);
    }

    #[test]
    fn an_address_must_start_with_a_digit() {
        assert_eq!(parse_address("0x401000").unwrap(), 0x401000);
        assert_eq!(parse_address("4198400").unwrap(), 4198400);
        assert!(parse_address("main").is_err());
        assert!(parse_address("").is_err());
    }

    /// Every tool publishes a title, annotations, a description and an
    /// `outputSchema` — asserted rather than assumed. The macro already makes
    /// `title` and `annotations` compile-time requirements; `outputSchema` it
    /// cannot, because a tool returning `CallToolResponse` has no payload type in
    /// its signature — so that is the one this has to watch.
    #[test]
    fn every_tool_publishes_its_metadata() {
        for def in BnMcpServer::vibrev_tool_defs() {
            let tool = &def.tool;
            assert!(tool.title.is_some(), "{} has no title", tool.name);
            assert!(
                tool.annotations.is_some(),
                "{} has no annotations",
                tool.name
            );
            assert!(
                tool.output_schema.is_some(),
                "{} has no outputSchema — add `output = \"responses::T\"`",
                tool.name
            );
            assert!(
                tool.description.is_some(),
                "{} has no description",
                tool.name
            );
        }
    }

    /// This engine names its tools the way Binary Ninja does: `group.verb`.
    #[test]
    fn tool_names_are_group_dot_verb() {
        let names: Vec<String> = BnMcpServer::vibrev_tool_defs()
            .iter()
            .map(|d| d.name().to_owned())
            .collect();
        assert!(!names.is_empty());
        for name in &names {
            assert!(
                name.split_once('.')
                    .is_some_and(|(g, v)| !g.is_empty() && !v.is_empty()),
                "{name} is not group.verb"
            );
        }
    }

    /// Every mutating tool must go through `Engine::write`, and this is the only
    /// place that can check it.
    ///
    /// `read` allows four concurrent calls; `write` takes a mutex first. A tool
    /// that changes the view and takes the `read` path is a race that shows up as
    /// wrong `bytes_before` / `bytes_after` rather than as a crash, and
    /// `patch.assemble` sizes a NOP-fill against a length it read before someone
    /// else's write landed. The rule is mechanical, so the check is too — it reads
    /// this file, because the routing is a property of the source and not of any
    /// value the type system sees.
    #[test]
    fn every_mutating_tool_takes_the_write_path() {
        let source = include_str!("mod.rs");
        // Each tool is `#[vibrev_tool( ... )]` followed by its `pub async fn`;
        // the body runs until the next attribute.
        let chunks: Vec<&str> = source.split("#[vibrev_tool(").skip(1).collect();
        let mut checked = 0;
        for chunk in chunks {
            let Some((attribute, body)) = chunk.split_once(")]") else {
                continue;
            };
            if !attribute.contains("read_only = false") {
                continue;
            }
            let name = body
                .split("pub async fn ")
                .nth(1)
                .and_then(|rest| rest.split('(').next())
                .unwrap_or("<unnamed>")
                .trim();
            checked += 1;
            // `.script(` counts: `Engine::script` takes the same lock, because a
            // script can do anything a write tool can.
            let routed = body.contains(".write(") || body.contains(".script(");
            let delegates = body.contains("self.structured_patch(");
            assert!(
                routed || delegates,
                "{name} is annotated read_only = false but does not call \
                 Engine::write / Engine::script — see the doc on Engine::write"
            );
            if routed {
                assert!(
                    !body.contains(".engine\n            .read("),
                    "{name} calls both write and read on the engine"
                );
            }
        }
        assert!(
            checked >= 15,
            "only found {checked} mutating tools; the parser above has drifted \
             from the source and is no longer checking anything"
        );
    }

    /// Anything whose payload has a `total` or a full list must carry
    /// `analysis_coverage`. That is a convention rather than a type, so it needs
    /// a check that survives a new tool being added by someone who has not read
    /// it.
    #[test]
    fn tools_returning_aggregates_carry_analysis_coverage() {
        for def in BnMcpServer::vibrev_tool_defs() {
            let Some(schema) = &def.tool.output_schema else {
                continue;
            };
            let props = schema
                .get("properties")
                .and_then(|p| p.as_object())
                .cloned()
                .unwrap_or_default();
            let aggregate = props.contains_key("total") || props.contains_key("statistics");
            if aggregate {
                assert!(
                    props.contains_key("analysis_coverage"),
                    "{} reports an aggregate but publishes no analysis_coverage",
                    def.name()
                );
            }
        }
    }
}
