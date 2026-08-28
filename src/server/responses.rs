//! Response payloads, and therefore `outputSchema`.
//!
//! Two conventions hold across every type here.
//!
//! **Addresses are hex strings, never numbers.** `0x401000` survives a JSON
//! round trip; `4198400` is what a model has to be told to convert back, and
//! addresses above 2^53 stop round-tripping through JavaScript entirely.
//!
//! **Anything with a total or a full list carries `analysis_coverage`**, and a
//! borderline case gets the field rather than not. `il.pseudo_c` and
//! `disasm.function` are the deliberate omissions: each is a single function,
//! not an aggregate, and the worker settles analysis before it renders (see
//! [`crate::bn`]), so there is nothing for the field to warn about. A sibling
//! field would also stop `Rendered<T>` from printing them as bare text.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::bn::AnalysisCoverage;

/// One mapped range of the binary.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SegmentEntry {
    /// First address in the segment, hex.
    pub start: String,
    /// One past the last address, hex.
    pub end: String,
    /// `end - start`, in bytes.
    pub size: u64,
    /// `rwx`-style permissions, with `-` for each bit that is clear.
    pub permissions: String,
    /// Binary Ninja's `SegmentContainsCode` flag — **"the loader declared this",
    /// not "there is code here"**.
    ///
    /// [Measured] the ELF loader leaves both this and `contains_data` clear on
    /// every segment of `/bin/cat`, including the `r-x` one holding all 110
    /// functions. Read `permissions` to decide where code lives; these two say
    /// only whether the format's loader chose to annotate the segment.
    pub contains_code: bool,
    /// See [`contains_code`](Self::contains_code): the same caveat applies.
    pub contains_data: bool,
    /// False when a user or a plugin added this segment rather than the loader.
    pub auto_defined: bool,
}

/// Every segment in the view.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SegmentList {
    pub segments: Vec<SegmentEntry>,
    pub total: usize,
    pub analysis_coverage: AnalysisCoverage,
}

/// One named section, as the loader described it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SectionEntry {
    pub name: String,
    pub start: String,
    pub end: String,
    pub size: u64,
    /// Binary Ninja's `Semantics` for the section, e.g. `ReadOnlyCodeSectionSemantics`.
    pub semantics: String,
}

/// Every named section in the view.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SectionList {
    pub sections: Vec<SectionEntry>,
    pub total: usize,
    pub analysis_coverage: AnalysisCoverage,
}

/// One function, as it appears in a listing.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FunctionEntry {
    pub name: String,
    /// Entry address, hex.
    pub start: String,
    /// `highest_address - start + 1`. Binary Ninja functions are not required to
    /// be contiguous, so treat this as an extent rather than a byte count.
    pub size: u64,
    pub basic_blocks: usize,
    /// Binary Ninja's `SymbolType` for the function's symbol.
    pub symbol_type: String,
}

// Absence, not `null`, is how every paged payload here says there is no next
// page — the same answer the other engines give, so one client-side rule covers
// all of them.
/// One page of [`FunctionEntry`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FunctionPage {
    pub functions: Vec<FunctionEntry>,
    /// Functions matching `filter` across the whole view, not just this page.
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    /// Offset to pass for the next page. **Absent on the last page** — never
    /// `null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub analysis_coverage: AnalysisCoverage,
}

/// Calling functions of one target, deduplicated by start.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CallersPage {
    pub callers: Vec<FunctionEntry>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub analysis_coverage: AnalysisCoverage,
}

/// Called functions of one target, deduplicated by start.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CalleesPage {
    pub callees: Vec<FunctionEntry>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub analysis_coverage: AnalysisCoverage,
}

/// One discovered string.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StringEntry {
    pub address: String,
    pub content: String,
    /// Byte length as Binary Ninja measured it, including any terminator.
    pub length: usize,
    /// `ascii`, `utf8`, `utf16`, or `utf32`.
    pub encoding: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// One page of [`StringEntry`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StringPage {
    pub strings: Vec<StringEntry>,
    /// Strings matching `filter` across the whole view, not just this page.
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub analysis_coverage: AnalysisCoverage,
}

/// Decompiler output for one function.
///
/// **One field, on purpose.** `vibrev_kit::Rendered<T>` prints a payload as bare
/// text only when it is a single string field with a recognized name (`c_code` is
/// one). Add a sibling — an address, a name, even `analysis_coverage` — and the
/// whole thing renders as pretty-printed JSON with the source escaped onto one
/// line. The signature lives in the text instead, via the linear view's function
/// header.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PseudoC {
    pub c_code: String,
}

/// Linear disassembly for one function.
///
/// **One field, on purpose** — same reason as [`PseudoC`]. `listing` is a
/// recognized text key; a sibling would force the whole payload through JSON.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DisasmFunction {
    pub listing: String,
}

/// One code cross-reference. Address-level: `from` is an instruction, not a function.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CodeRef {
    /// Referencing instruction, hex.
    pub from: String,
    /// Function containing `from`, when analysis assigned one.
    pub from_function: Option<String>,
    /// Destination address, hex.
    pub to: String,
    /// Function containing `to`, when analysis assigned one.
    pub to_function: Option<String>,
}

/// One page of [`CodeRef`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CodeRefPage {
    pub refs: Vec<CodeRef>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub analysis_coverage: AnalysisCoverage,
}

/// Outcome of a rename.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RenameResult {
    /// Function entry point, hex. Not the address that was asked for — that one
    /// may have been anywhere inside the function.
    pub address: String,
    pub old_name: String,
    pub new_name: String,
    pub ok: bool,
}

/// What the binary is.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SurveyMetadata {
    pub input_path: String,
    /// The `BinaryViewType` that claimed the file: `ELF`, `Mach-O`, `PE`, `Raw`.
    pub view_type: String,
    pub platform: Option<String>,
    pub architecture: Option<String>,
    pub address_size_bits: usize,
    pub endianness: String,
    pub start: String,
    pub end: String,
    pub length: u64,
    pub entry_point: String,
}

/// Counts across the whole view.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SurveyStatistics {
    pub functions: usize,
    pub segments: usize,
    pub sections: usize,
    pub strings: usize,
    pub symbols: usize,
    pub imported_functions: usize,
    /// Functions with no callees, i.e. leaves of the call graph.
    pub leaf_functions: usize,
    /// Sum of every function's extent, in bytes.
    pub function_bytes: u64,
}

/// Bounds this survey applied, so a caller can tell "small binary" from "we
/// stopped counting".
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SurveyLimits {
    /// Functions actually examined. Equal to `statistics.functions` unless
    /// `functions_truncated` is set.
    pub functions_scanned: usize,
    pub functions_truncated: bool,
    pub max_functions_scanned: usize,
    /// How many entries `interesting_functions` was capped at.
    pub interesting_functions_limit: usize,
}

// Keep this aligned with the other engines' survey: same sections, same intent,
// and an import name buckets the same way on both, so an agent that has read one
// surface can read this one. That alignment is what pays for naming the tools
// `group.verb` here instead of flat.
/// One call's worth of orientation for a binary.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Survey {
    pub metadata: SurveyMetadata,
    pub statistics: SurveyStatistics,
    pub segments: Vec<SegmentEntry>,
    pub sections: Vec<SectionEntry>,
    /// Entry point functions, as Binary Ninja identified them.
    pub entry_points: Vec<FunctionEntry>,
    /// The largest functions by extent — the usual starting point for a binary
    /// nobody has looked at yet.
    pub interesting_functions: Vec<FunctionEntry>,
    /// Imported function names bucketed by a name-matching heuristic. Keys are
    /// stable (`crypto`, `network`, …, `other`); a key is absent when empty.
    pub imports_by_category: BTreeMap<String, Vec<String>>,
    pub limits: SurveyLimits,
    pub analysis_coverage: AnalysisCoverage,
}

/// A supervisor-side session: one worker process holding one `BinaryView`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ViewInfo {
    /// The handle every analysis tool takes as `view`. Opaque — do not parse
    /// it, and do not substitute the path.
    pub view: String,
    pub input_path: String,
    /// PID of the worker process holding this view, when the OS reported one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Seconds since this view was opened.
    pub age_secs: u64,
    /// Calls currently executing against this view, out of
    /// [`crate::bn::MAX_INFLIGHT`].
    pub inflight: usize,
}

/// Result of `session.open`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OpenResult {
    pub view: String,
    pub input_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// True when an existing view of the same path was returned instead of a new
    /// one being opened.
    pub reused: bool,
    pub message: String,
}

/// Result of `session.list`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ViewList {
    pub views: Vec<ViewInfo>,
    pub total: usize,
}

/// Result of `session.close`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CloseResult {
    pub view: String,
    pub closed: bool,
    pub message: String,
}

/// Supervisor liveness. No Binary Ninja, no view.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Health {
    pub status: String,
    pub open_views: usize,
    pub tools: usize,
    pub max_inflight_per_view: usize,
    pub message: String,
}

/// One symbol, as it appears in a listing.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SymbolEntry {
    pub name: String,
    /// Symbol address, hex.
    pub address: String,
    /// Binary Ninja's `SymbolType`, Debug format (e.g. `ImportedFunction`).
    pub symbol_type: String,
}

/// One page of [`SymbolEntry`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SymbolPage {
    pub symbols: Vec<SymbolEntry>,
    /// Symbols matching `filter` across the whole view, not just this page.
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub analysis_coverage: AnalysisCoverage,
}

/// One page of imported symbols ([`SymbolEntry`]).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ImportPage {
    pub imports: Vec<SymbolEntry>,
    /// Imports matching `filter` across the whole view, not just this page.
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub analysis_coverage: AnalysisCoverage,
}

/// Bytes read from the view. Not an aggregate — no `analysis_coverage`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryRead {
    /// Address the read started at, hex.
    pub address: String,
    /// Bytes actually returned. May be shorter than requested if the range
    /// is unmapped.
    pub length: usize,
    /// Lowercase hex of those bytes, no spaces.
    pub hex: String,
}

/// Global comment at one address.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CommentGet {
    pub address: String,
    /// Empty when none is set.
    pub comment: String,
}

/// Outcome of setting a global comment.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CommentSet {
    pub address: String,
    pub comment: String,
    pub ok: bool,
}

/// One native basic block.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BasicBlockEntry {
    /// First address of the block, hex.
    pub start: String,
    /// One past the last address, hex.
    pub end: String,
    /// `end - start`, in bytes.
    pub size: u64,
    /// Start addresses of successor blocks, hex.
    pub successors: Vec<String>,
}

/// One page of [`BasicBlockEntry`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BasicBlockPage {
    pub blocks: Vec<BasicBlockEntry>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub analysis_coverage: AnalysisCoverage,
}

/// Caps `function.analyze` advertised and applied.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalyzeLimits {
    pub max_callers: usize,
    pub max_callees: usize,
    pub max_strings: usize,
}

/// Orientation dossier for one function. No decompile, no listing.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FunctionAnalyze {
    pub name: String,
    /// Function entry, hex.
    pub start: String,
    /// `highest_address - start + 1`. An extent, not a byte count.
    pub size: u64,
    /// How many native basic blocks the function has.
    pub basic_blocks: usize,
    pub callers: Vec<FunctionEntry>,
    pub callees: Vec<FunctionEntry>,
    /// Callers before the cap.
    pub caller_count: usize,
    /// Callees before the cap.
    pub callee_count: usize,
    pub callers_truncated: bool,
    pub callees_truncated: bool,
    /// Strings whose address is data-referenced from inside the function.
    pub referenced_strings: Vec<StringEntry>,
    pub limits: AnalyzeLimits,
    pub analysis_coverage: AnalysisCoverage,
}

/// Linear disassembly for an address range.
///
/// **One field, on purpose** — same reason as [`DisasmFunction`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DisasmRange {
    pub listing: String,
    /// True when `limit` stopped the listing before the range ended.
    pub truncated: bool,
}

/// One type, variable or function produced by the C parser.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ParsedTypeEntry {
    pub name: String,
    /// `Type`'s Display form.
    pub declaration: String,
}

/// Result of parsing C declarations. Not an analysis aggregate.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TypeParseResult {
    pub types: Vec<ParsedTypeEntry>,
    pub variables: Vec<ParsedTypeEntry>,
    pub functions: Vec<ParsedTypeEntry>,
}

/// A named type as stored on the view.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TypeQuery {
    pub name: String,
    pub declaration: String,
}

/// Outcome of defining a user type.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TypeApply {
    pub name: String,
    pub declaration: String,
    pub ok: bool,
}

/// Outcome of writing a `.bndb`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreateDatabase {
    pub path: String,
    pub created: bool,
    pub message: String,
}

/// Outcome of saving the current view.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SaveDatabase {
    pub saved: bool,
    pub message: String,
}

/// Which way `analyze.trace_data_flow` walks xrefs. Not a call-graph direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TraceDirection {
    #[default]
    Forward,
    Backward,
}

/// Code vs data classification on a `trace_data_flow` node or edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TraceRefKind {
    Code,
    Data,
}

/// One address visited by `analyze.trace_data_flow`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TraceDataFlowNode {
    /// The address, hex.
    pub addr: String,
    /// Enclosing function name, when analysis assigned one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub func: Option<String>,
    /// `code` when the address sits in a function, otherwise `data`.
    pub r#type: TraceRefKind,
    /// BFS distance from the start address.
    pub depth: usize,
}

/// One xref hop in a `trace_data_flow` walk.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TraceDataFlowEdge {
    pub from: String,
    pub to: String,
    /// `code` when the xref is a code reference, otherwise `data`.
    pub r#type: TraceRefKind,
}

/// Caps `analyze.trace_data_flow` advertised and applied.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TraceDataFlowLimits {
    pub max_depth: usize,
    pub max_nodes: usize,
    pub max_edges: usize,
    pub nodes_truncated: bool,
    pub edges_truncated: bool,
}

/// Bounded BFS over xrefs, not a call graph.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TraceDataFlow {
    /// Start address, hex.
    pub start: String,
    pub direction: TraceDirection,
    /// Largest node depth actually reached.
    pub depth_reached: usize,
    pub nodes: Vec<TraceDataFlowNode>,
    pub edges: Vec<TraceDataFlowEdge>,
    pub limits: TraceDataFlowLimits,
    pub analysis_coverage: AnalysisCoverage,
}

/// What one `script.python` run produced.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScriptRun {
    /// True when the script ran to the end without raising.
    ///
    /// False covers a raised exception, an interrupt, and a runner that never
    /// answered — `error` says which.
    pub ok: bool,
    /// Everything the script wrote to stdout and stderr, in order.
    ///
    /// Captured inside Python, so it is the script's own output and nothing
    /// else. Capped; see `truncated`.
    pub stdout: String,
    /// Whatever the script left in a variable named `result`.
    ///
    /// JSON when the value is JSON-serializable, its `repr()` otherwise, and
    /// absent when the script never set it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// The Python traceback, when the script raised.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// True when `stdout` hit the cap and lost its tail.
    pub truncated: bool,
    /// True when the script was still running at the timeout and was interrupted.
    ///
    /// The interrupt arrives as a `KeyboardInterrupt` *inside* the script, so
    /// `stdout` still holds whatever it printed before that point.
    pub timed_out: bool,
    /// Wall-clock seconds, including the wait for the interpreter.
    pub elapsed_secs: f64,
    /// Sampled before the script ran, like every other aggregate.
    ///
    /// A script that counts functions is as wrong on an unconverged view as
    /// `binary.functions` is.
    pub analysis_coverage: AnalysisCoverage,
}

/// Outcome of clearing the Python namespace.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScriptReset {
    pub ok: bool,
    pub message: String,
}

/// A function's own comment — the one attached to the function, not to an
/// address inside it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FunctionCommentGet {
    /// The function's entry address, hex.
    pub address: String,
    pub name: String,
    /// Empty when the function has no comment.
    pub comment: String,
}

/// Outcome of setting a function's own comment.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FunctionCommentSet {
    pub address: String,
    pub name: String,
    pub comment: String,
    pub ok: bool,
}

/// One variable Binary Ninja recovered for a function.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VariableEntry {
    /// The name as it appears in pseudocode.
    pub name: String,
    /// The variable's type, as a C declaration.
    pub r#type: String,
    /// `register`, `stack` or `flag` — where the variable lives.
    pub storage_class: String,
    /// Stack offset for a stack variable, register index otherwise. Signed:
    /// stack offsets below the frame pointer are negative.
    pub storage: i64,
    /// False when a user pinned this name or type, true when analysis chose it.
    ///
    /// A rename or retype flips this, and analysis will not overwrite it again.
    pub auto_defined: bool,
}

/// One page of a function's variables.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VariablePage {
    /// The function these belong to, hex.
    pub address: String,
    pub name: String,
    pub variables: Vec<VariableEntry>,
    /// Variables in the whole function, not just this page.
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub analysis_coverage: AnalysisCoverage,
}

/// Outcome of renaming or retyping one variable.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VariableSet {
    /// The function, hex.
    pub address: String,
    pub function: String,
    /// The variable as it was before this call.
    pub before: VariableEntry,
    /// The variable as Binary Ninja reports it now, read back rather than assumed.
    pub after: VariableEntry,
    pub ok: bool,
}

/// Outcome of setting a function's prototype.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FunctionPrototype {
    pub address: String,
    pub name: String,
    /// The signature before this call.
    pub before: String,
    /// The signature Binary Ninja reports now, read back rather than assumed.
    pub after: String,
    pub ok: bool,
}

/// A `SymbolType`, as a `binary.symbols` filter.
///
/// This is a parameter rather than a family of tools. `binary.exports` and
/// `binary.locals` would be the same query with a constant substituted, which is
/// an argument rather than a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    /// A function defined in this binary. With no import, this is the export set.
    Function,
    /// A function this binary imports.
    ImportedFunction,
    /// A slot in the import table.
    ImportAddress,
    /// Data defined in this binary.
    Data,
    /// Data this binary imports.
    ImportedData,
    /// A symbol resolved outside this binary.
    External,
    /// A function from a type library.
    LibraryFunction,
    /// A function Binary Ninja named symbolically.
    ///
    /// Spelled the way `SymbolEntry::symbol_type` reports it, so a value read
    /// out of a response can be passed straight back in as `kind`.
    Symbolic,
    /// A label local to one function.
    LocalLabel,
}

/// One data variable analysis recovered or a user defined.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DataVarEntry {
    /// Address, hex.
    pub address: String,
    /// The symbol name at that address, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The variable's type, as a C declaration.
    pub r#type: String,
    /// Size in bytes, when the type has a known one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// False when a user defined this variable, true when analysis found it.
    pub auto_discovered: bool,
}

/// One page of data variables.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DataVarPage {
    pub data_vars: Vec<DataVarEntry>,
    /// Data variables in the whole view, not just this page.
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub analysis_coverage: AnalysisCoverage,
}

/// What `binary.search` is looking for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchKind {
    /// A hex byte pattern: `4889e5`, `48 89 e5`.
    #[default]
    Bytes,
    /// A substring of the rendered disassembly.
    Text,
    /// An integer that appears as a constant in an instruction.
    Constant,
}

/// One hit.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SearchHit {
    /// Address of the match, hex.
    pub address: String,
    /// Enclosing function, when the hit is inside one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
}

/// Matches for one `binary.search`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SearchResult {
    pub kind: SearchKind,
    /// The query as it was interpreted, after normalization.
    pub query: String,
    /// Where the scan started and stopped, hex.
    pub start: String,
    pub end: String,
    pub hits: Vec<SearchHit>,
    /// True when the scan stopped at `limit` rather than at `end`.
    ///
    /// `hits.len()` is then a floor on how many matches exist, not a count.
    pub truncated: bool,
    pub analysis_coverage: AnalysisCoverage,
}

/// Outcome of renaming a symbol that is not a function.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SymbolRename {
    pub address: String,
    pub old_name: String,
    pub new_name: String,
    /// The `SymbolType` that was preserved across the rename.
    pub symbol_type: String,
    pub ok: bool,
}

// One core call, one tool. There is no `BNNeverBranch` in the headers — Python's
// `never_branch` forwards to `BNConvertToNop` — so an engine that ships both
// names is publishing two tools for one operation.
/// Which structured patch to apply.
///
/// There is no `never_branch`: Binary Ninja's Python exposes that name, but it
/// and `nop` are the same core call, `BNConvertToNop`. Making a conditional jump
/// never taken *is* NOPing it, and this surface does not ship two names for one
/// question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PatchOperation {
    /// Replace the instruction with NOPs. Also spelled "never branch".
    Nop,
    /// Make a conditional branch unconditional.
    AlwaysBranch,
    /// Flip a conditional branch's sense.
    InvertBranch,
    /// Skip a call and leave a value in the return register.
    SkipAndReturn,
}

/// What Binary Ninja will accept at one address.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PatchAvailability {
    /// The address asked about, hex.
    pub address: String,
    /// Enclosing function, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Length of the instruction there. Zero when nothing decodes.
    pub instruction_length: usize,
    /// The instruction's current bytes, hex.
    pub bytes: String,
    /// How it disassembles right now.
    pub listing: String,
    /// True whenever an instruction decodes here: `patch.nop` replaces any
    /// instruction, not only a branch.
    ///
    /// Deliberately not Binary Ninja's `IsNeverBranchPatchAvailable`, which
    /// answers the narrower branch question — [measured] it says `false` for
    /// `push rbp`, which `patch.nop` then NOPs successfully.
    pub can_nop: bool,
    /// True when this is a branch, so NOPing it has the specific meaning
    /// "never taken". `patch.nop` is the tool either way.
    pub can_never_branch: bool,
    pub can_always_branch: bool,
    pub can_invert_branch: bool,
    pub can_skip_and_return: bool,
    /// False when this Binary Ninja install has no assembler for the
    /// architecture, which makes `patch.assemble` unusable here.
    pub can_assemble: bool,
}

/// Outcome of a patch. Every field is read back rather than predicted.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PatchResult {
    /// Where the patch landed, hex.
    pub address: String,
    /// What was done. `assemble` and `bytes` name themselves.
    pub operation: String,
    /// The bytes that were there before, hex.
    pub bytes_before: String,
    /// The bytes there now, hex, re-read after analysis settled.
    pub bytes_after: String,
    /// How it disassembled before.
    pub listing_before: String,
    /// How it disassembles now.
    pub listing_after: String,
    /// Bytes actually written. A short write is an error, never a quiet result.
    pub bytes_written: usize,
    /// NOP bytes added to fill out the instruction the patch replaced.
    ///
    /// Non-zero when the new encoding is shorter than the old one. Without the
    /// padding the tail of the old instruction would decode as garbage.
    pub padding_bytes: usize,
    pub ok: bool,
    /// Anything the caller should know that the fields above do not say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Patches are in memory only. This says what would persist them.
    pub persistence: String,
}

/// Outcome of writing the patched binary out.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExportBinary {
    pub path: String,
    pub written: bool,
    pub message: String,
}

/// Outcome of reverting the newest patch.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PatchRevert {
    pub ok: bool,
    /// What Binary Ninja said the reverted entry contained, one line per action.
    ///
    /// e.g. `Wrote data of length 0x1 at offset 0x2040`. This is the engine's
    /// own description, not a reconstruction — it is the only account of what
    /// actually came back.
    pub reverted: Vec<String>,
    /// Addresses named by the reverted actions, hex, when they could be parsed
    /// out of the summaries above.
    ///
    /// A convenience for re-reading the affected bytes; the summaries are the
    /// authoritative record.
    pub addresses: Vec<String>,
    /// What is on top of the undo stack now — the next thing `patch.revert`
    /// would look at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    /// How many entries remain that this tool would revert.
    pub reverts_remaining: usize,
    pub message: String,
}
