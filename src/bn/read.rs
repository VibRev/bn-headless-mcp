//! Turning Binary Ninja objects into the response payloads.
//!
//! Every function here runs on a blocking thread inside
//! [`Engine::read`](super::Engine::read), so analysis has already settled by the
//! time any of them is called. None of them may block for long on its own —
//! rendering Pseudo C or a disassembly listing is the exception
//! ([`super::pseudo_c`], [`super::disasm`]).
//!
//! A note on the API, because it costs an hour to rediscover: `Array<T>::iter()`
//! yields `Guard<'_, T>` for most types, which derefs to `&T` and whose
//! *inherent* `clone()` returns `Ref<T>`. `CodeReference`'s `Wrapped` is `Self`
//! (owned); `StringReference` is `Copy`. The array has to be bound to a local
//! first — iterating a temporary borrows something that is already gone.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use binaryninja::binary_view::{
    BinaryView, BinaryViewBase, BinaryViewExt, StringReference, StringType,
};
use binaryninja::data_buffer::DataBuffer;
use binaryninja::file_metadata::SaveSettings;
use binaryninja::function::{Function, FunctionViewType};
use binaryninja::rc::Ref;
use binaryninja::string::BnString;
use binaryninja::symbol::{Symbol, SymbolType};
use binaryninja::types::Type;
use binaryninja::variable::{DataVariable, NamedVariableWithType, VariableSourceType};
use binaryninja::Endianness;

use crate::bn::AnalysisCoverage;
use crate::error::ToolError;
use crate::server::responses::{
    AnalyzeLimits, BasicBlockEntry, CodeRef, DataVarEntry, FunctionAnalyze, FunctionEntry,
    FunctionPrototype, ParsedTypeEntry, SearchHit, SearchKind, SearchResult, SectionEntry,
    SegmentEntry, StringEntry, SurveyMetadata, SurveyStatistics, SymbolEntry, SymbolKind,
    SymbolRename, TraceDataFlow, TraceDataFlowEdge, TraceDataFlowLimits, TraceDataFlowNode,
    TraceDirection, TraceRefKind, TypeApply, TypeParseResult, TypeQuery, VariableEntry,
    VariableSet,
};

/// Displayed string content is capped here; `StringEntry::truncated` flags a cut.
const DISPLAYED_STRING_CHARS: usize = 256;

/// Cap on how many functions a survey will walk. Binary Ninja will happily hand
/// back a firmware image's 200k functions; a survey is meant to be read by a
/// model, and `limits.functions_truncated` says when we stopped.
pub const MAX_SURVEY_FUNCTIONS: usize = 20_000;
/// How many entries `interesting_functions` holds.
pub const INTERESTING_FUNCTIONS: usize = 20;

/// Hard cap on a single `memory.read`.
pub const MEMORY_READ_MAX: usize = 65_536;

/// Caps for `function.analyze`.
pub const ANALYZE_MAX_CALLERS: usize = 50;
pub const ANALYZE_MAX_CALLEES: usize = 50;
pub const ANALYZE_MAX_STRINGS: usize = 20;

/// Caps for `analyze.trace_data_flow`.
pub const TRACE_MAX_NODES: usize = 200;
pub const TRACE_MAX_EDGES: usize = 500;
pub const TRACE_DEFAULT_DEPTH: usize = 5;
pub const TRACE_MAX_DEPTH: usize = 20;

const NO_INCLUDE_DIRS: &[BnString] = &[];

pub fn hex(addr: u64) -> String {
    format!("{addr:#x}")
}

/// The best display name for a function.
///
/// `full_name` is the demangled one where a demangler ran, which is what a
/// person or a model wants to read. `.short_name()` drops namespaces and
/// `.raw_name()` gives the mangled original — both are worse defaults, and this
/// revision of the API has no plain `.name()` to fall back on.
pub fn function_name(func: &Function) -> String {
    symbol_name(&func.symbol())
}

pub fn symbol_name(sym: &Symbol) -> String {
    sym.full_name().to_string_lossy().into_owned()
}

fn symbol_type_name(sym: &Symbol) -> String {
    format!("{:?}", sym.sym_type())
}

/// Function extent, not byte count: Binary Ninja functions may be discontiguous,
/// so this is `highest - start + 1` and can overstate a chunked function.
pub fn function_extent(func: &Function) -> u64 {
    func.highest_address().saturating_sub(func.start()) + 1
}

pub fn function_entry(func: &Function) -> FunctionEntry {
    let symbol = func.symbol();
    FunctionEntry {
        name: symbol_name(&symbol),
        start: hex(func.start()),
        size: function_extent(func),
        basic_blocks: func.basic_blocks().len(),
        symbol_type: symbol_type_name(&symbol),
    }
}

pub fn segments(view: &BinaryView) -> Vec<SegmentEntry> {
    let segments = view.segments();
    segments
        .iter()
        .map(|segment| {
            let range = segment.address_range();
            SegmentEntry {
                start: hex(range.start),
                end: hex(range.end),
                size: range.end.saturating_sub(range.start),
                permissions: permissions(
                    segment.readable(),
                    segment.writable(),
                    segment.executable(),
                ),
                contains_code: segment.contains_code(),
                contains_data: segment.contains_data(),
                auto_defined: segment.auto_defined(),
            }
        })
        .collect()
}

fn permissions(r: bool, w: bool, x: bool) -> String {
    let mut out = String::with_capacity(3);
    out.push(if r { 'r' } else { '-' });
    out.push(if w { 'w' } else { '-' });
    out.push(if x { 'x' } else { '-' });
    out
}

pub fn sections(view: &BinaryView) -> Vec<SectionEntry> {
    let sections = view.sections();
    sections
        .iter()
        .map(|section| {
            let range = section.address_range();
            SectionEntry {
                name: section.name().to_string_lossy().into_owned(),
                start: hex(range.start),
                end: hex(range.end),
                size: range.end.saturating_sub(range.start),
                semantics: format!("{:?}", section.semantics()),
            }
        })
        .collect()
}

/// Functions matching `filter`, in address order, as one page.
///
/// Returns `(page, total)` where `total` counts every match, not just this page.
/// Counting the whole set rather than the scanned prefix is what makes paging
/// work at all: a `total` that stops at `limit` puts `next_offset` arithmetically
/// out of reach, so every call reads as "that was all of them".
///
/// Address order, not name order: it is stable across reruns, and paging through
/// a list whose order can change is how a caller silently skips entries.
pub fn function_page(
    view: &BinaryView,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
) -> (Vec<FunctionEntry>, usize) {
    let needle = filter.map(str::to_lowercase);
    let mut matched: Vec<FunctionEntry> = Vec::new();
    let mut total = 0usize;

    let all = view.functions();
    let mut functions: Vec<Ref<Function>> = all.iter().map(|f| f.clone()).collect();
    functions.sort_by_key(|f| f.start());

    for func in &functions {
        let entry = function_entry(func);
        if let Some(needle) = &needle {
            if !entry.name.to_lowercase().contains(needle.as_str()) {
                continue;
            }
        }
        if total >= offset && matched.len() < limit {
            matched.push(entry);
        }
        total += 1;
    }
    (matched, total)
}

/// Strings matching `filter`, in address order, as one page.
///
/// Without a filter the whole set is counted from the references alone and only
/// the page is decoded. With a filter every string has to be decoded to match,
/// then the match set is paged.
pub fn string_page(
    view: &BinaryView,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
) -> (Vec<StringEntry>, usize) {
    let all = view.strings();
    let mut refs: Vec<StringReference> = all.iter().collect();
    refs.sort_by_key(|r| r.start);

    let needle = filter.filter(|s| !s.is_empty()).map(str::to_lowercase);
    match needle {
        None => {
            let total = refs.len();
            let page = refs
                .iter()
                .skip(offset)
                .take(limit)
                .map(|r| string_entry(view, r))
                .collect();
            (page, total)
        }
        Some(needle) => {
            let mut matched = Vec::new();
            let mut total = 0usize;
            for sref in &refs {
                let decoded = decode_string(view, sref);
                if !decoded.to_lowercase().contains(needle.as_str()) {
                    continue;
                }
                if total >= offset && matched.len() < limit {
                    matched.push(string_entry_from(sref, decoded));
                }
                total += 1;
            }
            (matched, total)
        }
    }
}

/// Decode one BN string reference, respecting the view's endianness.
///
/// The terminator Binary Ninja includes in `length` is stripped. Display
/// truncation is applied when the entry is built, not here, so a filter can
/// still match past the first 256 characters.
pub fn decode_string(view: &BinaryView, sref: &StringReference) -> String {
    let bytes = view.read_vec(sref.start, sref.length);
    let little = matches!(view.default_endianness(), Endianness::LittleEndian);
    let mut decoded = match sref.ty {
        StringType::AsciiString | StringType::Utf8String => {
            String::from_utf8_lossy(&bytes).into_owned()
        }
        StringType::Utf16String => decode_utf16(&bytes, little),
        StringType::Utf32String => decode_utf32(&bytes, little),
    };
    while decoded.ends_with('\0') {
        decoded.pop();
    }
    decoded
}

fn string_encoding(ty: StringType) -> &'static str {
    match ty {
        StringType::AsciiString => "ascii",
        StringType::Utf8String => "utf8",
        StringType::Utf16String => "utf16",
        StringType::Utf32String => "utf32",
    }
}

// Here and in `decode_utf32`, the remainder half of `as_chunks` is dropped on
// purpose: a tail too short to complete a code unit has nothing to decode into.
// BN's `length` spans whole units, so a non-empty remainder means the entry was
// truncated or misclassified, and inventing a padded final unit for it would
// put a character in the output that is not in the binary.
fn decode_utf16(bytes: &[u8], little: bool) -> String {
    let (pairs, _tail) = bytes.as_chunks::<2>();
    let units: Vec<u16> = pairs
        .iter()
        .map(|&c| {
            if little {
                u16::from_le_bytes(c)
            } else {
                u16::from_be_bytes(c)
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

fn decode_utf32(bytes: &[u8], little: bool) -> String {
    let (quads, _tail) = bytes.as_chunks::<4>();
    quads
        .iter()
        .map(|&c| {
            let cp = if little {
                u32::from_le_bytes(c)
            } else {
                u32::from_be_bytes(c)
            };
            char::from_u32(cp).unwrap_or(char::REPLACEMENT_CHARACTER)
        })
        .collect()
}

fn truncate_chars(s: String, cap: usize) -> (String, bool) {
    let mut chars = s.chars();
    let content: String = chars.by_ref().take(cap).collect();
    let truncated = chars.next().is_some();
    (content, truncated)
}

fn string_entry(view: &BinaryView, sref: &StringReference) -> StringEntry {
    string_entry_from(sref, decode_string(view, sref))
}

fn string_entry_from(sref: &StringReference, decoded: String) -> StringEntry {
    let (content, truncated) = truncate_chars(decoded, DISPLAYED_STRING_CHARS);
    StringEntry {
        address: hex(sref.start),
        content,
        length: sref.length,
        encoding: string_encoding(sref.ty).to_owned(),
        truncated,
    }
}

/// Code references *to* `addr`. Sorted by the referencing instruction.
pub fn code_refs_to(view: &BinaryView, addr: u64) -> Vec<CodeRef> {
    let to_function = function_name_at(view, addr);
    let refs = view.code_refs_to_addr(addr);
    let mut out: Vec<(u64, CodeRef)> = refs
        .iter()
        .map(|r| {
            (
                r.address,
                CodeRef {
                    from: hex(r.address),
                    from_function: r.func.as_ref().map(|f| function_name(f)),
                    to: hex(addr),
                    to_function: to_function.clone(),
                },
            )
        })
        .collect();
    sort_refs(&mut out);
    out.into_iter().map(|(_, r)| r).collect()
}

/// Code references *from* `addr`. Sorted by destination.
///
/// `containing_func` is the function that holds `addr`, when there is one —
/// `code_refs_from_addr` uses it to recover dests that are only known in that
/// function's IL.
pub fn code_refs_from(view: &BinaryView, addr: u64) -> Vec<CodeRef> {
    let containing = resolve_function(view, Some(addr), None);
    let mut dests = view.code_refs_from_addr(addr, containing.as_deref());
    dests.sort_unstable();
    let from_function = containing.as_ref().map(|f| function_name(f));
    dests
        .into_iter()
        .map(|dest| CodeRef {
            from: hex(addr),
            from_function: from_function.clone(),
            to: hex(dest),
            to_function: function_name_at(view, dest),
        })
        .collect()
}

/// The function containing `addr`, by name. Public alias for the internal
/// helper, so the patch tools can label a hit without duplicating the lookup.
pub fn function_name_at_address(view: &BinaryView, addr: u64) -> Option<String> {
    function_name_at(view, addr)
}

fn function_name_at(view: &BinaryView, addr: u64) -> Option<String> {
    resolve_function(view, Some(addr), None).map(|f| function_name(&f))
}

/// Tie-break same-address refs by function name. One instruction can sit in
/// several functions (thunks / overlapping ranges); Array iteration order is
/// not stable across process starts.
fn sort_refs(refs: &mut [(u64, CodeRef)]) {
    refs.sort_by(|a, b| {
        a.0.cmp(&b.0).then_with(|| {
            a.1.from_function
                .as_deref()
                .cmp(&b.1.from_function.as_deref())
                .then_with(|| a.1.to_function.as_deref().cmp(&b.1.to_function.as_deref()))
        })
    });
}

/// Functions that call `func`, deduplicated by start and sorted by start.
pub fn callers(func: &Function) -> Vec<FunctionEntry> {
    let sites = func.caller_sites();
    let mut by_start: BTreeMap<u64, FunctionEntry> = BTreeMap::new();
    for site in sites.iter() {
        if let Some(caller) = site.func.as_ref() {
            by_start
                .entry(caller.start())
                .or_insert_with(|| function_entry(caller));
        }
    }
    by_start.into_values().collect()
}

/// Functions `func` calls, from `call_sites` plus `code_refs_from_addr`.
///
/// `call_sites` includes unresolved indirect jumps; destinations that do not
/// resolve to a function are skipped. Deduplicated and sorted by start.
pub fn callees(view: &BinaryView, func: &Function) -> Vec<FunctionEntry> {
    let sites = func.call_sites();
    let mut by_start: BTreeMap<u64, FunctionEntry> = BTreeMap::new();
    for site in sites.iter() {
        let dests = view.code_refs_from_addr(site.address, Some(func));
        for dest in dests {
            if let Some(callee) = resolve_function(view, Some(dest), None) {
                by_start
                    .entry(callee.start())
                    .or_insert_with(|| function_entry(&callee));
            }
        }
    }
    by_start.into_values().collect()
}

/// Resolve a target to an address: an address is used as-is, a name becomes
/// that function's start.
pub fn resolve_target_address(
    view: &BinaryView,
    address: Option<u64>,
    name: Option<&str>,
) -> Result<u64, ToolError> {
    if let Some(addr) = address {
        return Ok(addr);
    }
    let Some(name) = name else {
        return Err(ToolError::InvalidParams(
            "target is empty; give a function name or an address".to_owned(),
        ));
    };
    match resolve_function(view, None, Some(name)) {
        Some(func) => Ok(func.start()),
        None => Err(ToolError::NotFound(format!(
            "no function matches {name:?}. Use binary.functions to list what analysis found."
        ))),
    }
}

/// Resolve a target to a function.
///
/// An address anywhere inside a function resolves to that function, not only its
/// start: the addresses a caller has to hand come out of disassembly and xrefs,
/// and those point into a body. A name must match exactly. Returns `None` rather
/// than guessing when nothing matches — a rename applied to the wrong function is
/// not recoverable from the response.
pub fn resolve_function(
    view: &BinaryView,
    address: Option<u64>,
    name: Option<&str>,
) -> Option<Ref<Function>> {
    if let Some(addr) = address {
        let containing = view.functions_containing(addr);
        if let Some(func) = containing.iter().next() {
            return Some(func.clone());
        }
        // Nothing contains it; an exact-start lookup still helps when analysis
        // knows of a function whose body is empty.
        let at = view.functions_at(addr);
        return at.iter().next().map(|f| f.clone());
    }
    let name = name?;
    let all = view.functions();
    all.iter()
        .find(|f| function_name(f) == name)
        .map(|f| f.clone())
}

pub fn metadata(view: &BinaryView, input_path: &str) -> SurveyMetadata {
    SurveyMetadata {
        input_path: input_path.to_owned(),
        view_type: view.view_type(),
        platform: view.default_platform().map(|p| p.name()),
        architecture: view.default_arch().map(|a| a.name()),
        address_size_bits: view.address_size() * 8,
        endianness: format!("{:?}", view.default_endianness()),
        start: hex(view.start()),
        end: hex(view.end()),
        length: view.len(),
        entry_point: hex(view.entry_point()),
    }
}

/// Everything a survey needs from the function list, in one walk.
///
/// One pass, because walking `bv.functions()` is the expensive part of a survey
/// and three passes for three numbers cost three times as much for no extra
/// information.
pub struct FunctionSummary {
    pub scanned: usize,
    pub truncated: bool,
    pub available: usize,
    pub total_bytes: u64,
    pub leaves: usize,
    pub interesting: Vec<FunctionEntry>,
}

pub fn summarize_functions(view: &BinaryView) -> FunctionSummary {
    let mut scanned = 0usize;
    let mut total_bytes = 0u64;
    let mut leaves = 0usize;
    // Kept sorted by descending extent and truncated, so memory stays bounded on
    // a firmware image.
    let mut interesting: Vec<(u64, FunctionEntry)> = Vec::new();

    let functions = view.functions();
    let available = functions.len();
    for func in functions.iter() {
        if scanned >= MAX_SURVEY_FUNCTIONS {
            break;
        }
        scanned += 1;
        let extent = function_extent(&func);
        total_bytes += extent;
        // `call_sites` includes unresolved indirect jumps, so this undercounts
        // leaves rather than inventing them. Named accordingly in the schema.
        if func.call_sites().is_empty() {
            leaves += 1;
        }
        if interesting.len() < INTERESTING_FUNCTIONS
            || interesting.last().is_some_and(|(size, _)| *size < extent)
        {
            interesting.push((extent, function_entry(&func)));
            interesting.sort_by_key(|(extent, _)| std::cmp::Reverse(*extent));
            interesting.truncate(INTERESTING_FUNCTIONS);
        }
    }

    FunctionSummary {
        scanned,
        truncated: available > scanned,
        available,
        total_bytes,
        leaves,
        interesting: interesting.into_iter().map(|(_, entry)| entry).collect(),
    }
}

pub fn statistics(
    view: &BinaryView,
    functions: &FunctionSummary,
    imported: usize,
) -> SurveyStatistics {
    SurveyStatistics {
        functions: functions.available,
        segments: view.segments().len(),
        sections: view.sections().len(),
        strings: view.strings().len(),
        symbols: view.symbols().len(),
        imported_functions: imported,
        leaf_functions: functions.leaves,
        function_bytes: functions.total_bytes,
    }
}

pub fn imported_function_names(view: &BinaryView) -> Vec<String> {
    let imported = view.symbols_of_type(SymbolType::ImportedFunction);
    let import_addr = view.symbols_of_type(SymbolType::ImportAddress);
    let mut names: Vec<String> = imported
        .iter()
        .chain(import_addr.iter())
        .map(|sym| symbol_name(&sym))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Substring rules for bucketing import names, first match wins.
///
/// A heuristic, and the tool description says so. It mirrors `ida-pro-mcp`'s
/// `_IMPORT_CATEGORIES` in shape and intent so that the same import lands in the
/// same bucket whichever engine a caller asks — that alignment is worth more than
/// any individual rule being clever.
const IMPORT_CATEGORIES: &[(&str, &[&str])] = &[
    (
        "crypto",
        &[
            "crypt", "aes", "sha1", "sha256", "sha512", "md5", "rsa", "hmac", "rand",
        ],
    ),
    (
        "network",
        &[
            "socket", "connect", "send", "recv", "bind", "listen", "accept", "dns", "http", "curl",
            "ssl", "tls",
        ],
    ),
    (
        "file",
        &[
            "open", "read", "write", "close", "stat", "fopen", "fread", "fwrite", "unlink",
            "mkdir", "dir",
        ],
    ),
    (
        "process",
        &[
            "exec", "fork", "spawn", "system", "popen", "kill", "signal", "thread", "pthread",
            "clone",
        ],
    ),
    (
        "memory",
        &[
            "malloc", "calloc", "realloc", "free", "mmap", "munmap", "memcpy", "memset", "memmove",
            "alloc",
        ],
    ),
    (
        "string",
        &[
            "str", "printf", "scanf", "snprintf", "wcs", "atoi", "strtol",
        ],
    ),
];

pub fn categorize_imports(names: &[String]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for name in names {
        let lowered = name.to_lowercase();
        let category = IMPORT_CATEGORIES
            .iter()
            .find(|(_, needles)| needles.iter().any(|n| lowered.contains(n)))
            .map(|(name, _)| *name)
            .unwrap_or("other");
        out.entry(category.to_owned())
            .or_default()
            .push(name.clone());
    }
    out
}

pub fn entry_point_functions(view: &BinaryView) -> Vec<FunctionEntry> {
    let entries = view.entry_point_functions();
    entries.iter().map(|f| function_entry(&f)).collect()
}

/// Give a function a user-defined name.
///
/// A *user* symbol, not an auto symbol: auto symbols are what analysis produces
/// and a later analysis pass is free to replace them, so a rename recorded that
/// way can silently revert. `undefine_user_symbol` first, because defining a
/// second user symbol at one address leaves both in place.
pub fn rename_function(view: &BinaryView, func: &Function, new_name: &str) -> Result<(), String> {
    let existing = func.symbol();
    let address = func.start();
    let replacement = Symbol::builder(existing.sym_type(), new_name, address)
        .full_name(new_name.to_owned())
        .short_name(new_name.to_owned())
        .create();
    view.undefine_user_symbol(&existing);
    view.define_user_symbol(&replacement);

    // Confirm rather than assume: `define_user_symbol` returns nothing, and a
    // rename that quietly did not happen is worse than one that failed loudly.
    let observed = view
        .symbol_by_raw_name(new_name)
        .map(|s| symbol_name(&s))
        .unwrap_or_default();
    if observed == new_name {
        Ok(())
    } else {
        Err(format!(
            "Binary Ninja accepted the symbol but reading it back at {} gave {observed:?}",
            hex(address)
        ))
    }
}

/// Data references *to* `addr`. Sorted by the referencing address.
pub fn data_refs_to(view: &BinaryView, addr: u64) -> Vec<CodeRef> {
    let to_function = function_name_at(view, addr);
    let refs = view.data_refs_to_addr(addr);
    let mut out: Vec<(u64, CodeRef)> = refs
        .iter()
        .map(|r| {
            (
                r.address,
                CodeRef {
                    from: hex(r.address),
                    from_function: function_name_at(view, r.address),
                    to: hex(addr),
                    to_function: to_function.clone(),
                },
            )
        })
        .collect();
    sort_refs(&mut out);
    out.into_iter().map(|(_, r)| r).collect()
}

/// Data references *from* `addr`. Sorted by destination.
pub fn data_refs_from(view: &BinaryView, addr: u64) -> Vec<CodeRef> {
    let from_function = function_name_at(view, addr);
    let refs = view.data_refs_from_addr(addr);
    let mut dests: Vec<u64> = refs.iter().map(|r| r.address).collect();
    dests.sort_unstable();
    dests
        .into_iter()
        .map(|dest| CodeRef {
            from: hex(addr),
            from_function: from_function.clone(),
            to: hex(dest),
            to_function: function_name_at(view, dest),
        })
        .collect()
}

fn symbol_entry(sym: &Symbol) -> SymbolEntry {
    SymbolEntry {
        name: symbol_name(sym),
        address: hex(sym.address()),
        symbol_type: symbol_type_name(sym),
    }
}

/// The `SymbolType` a [`SymbolKind`] selects.
pub fn symbol_kind_type(kind: SymbolKind) -> SymbolType {
    match kind {
        SymbolKind::Function => SymbolType::Function,
        SymbolKind::ImportedFunction => SymbolType::ImportedFunction,
        SymbolKind::ImportAddress => SymbolType::ImportAddress,
        SymbolKind::Data => SymbolType::Data,
        SymbolKind::ImportedData => SymbolType::ImportedData,
        SymbolKind::External => SymbolType::External,
        SymbolKind::LibraryFunction => SymbolType::LibraryFunction,
        SymbolKind::Symbolic => SymbolType::Symbolic,
        SymbolKind::LocalLabel => SymbolType::LocalLabel,
    }
}

/// Symbols matching `filter` and `kind`, in address order, as one page.
///
/// `kind` uses `symbols_of_type` rather than filtering the full list, which is
/// both faster and the same set Binary Ninja itself would report — the `Data`
/// kind, for instance, is not simply "everything that is not a function".
pub fn symbol_page(
    view: &BinaryView,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
    kind: Option<SymbolKind>,
) -> (Vec<SymbolEntry>, usize) {
    let needle = filter.map(str::to_lowercase);
    let all = match kind {
        Some(kind) => view.symbols_of_type(symbol_kind_type(kind)),
        None => view.symbols(),
    };
    let mut symbols: Vec<Ref<Symbol>> = all.iter().map(|s| s.clone()).collect();
    symbols.sort_by_key(|s| s.address());

    let mut matched = Vec::new();
    let mut total = 0usize;
    for sym in &symbols {
        let entry = symbol_entry(sym);
        if let Some(needle) = &needle {
            if !entry.name.to_lowercase().contains(needle.as_str()) {
                continue;
            }
        }
        if total >= offset && matched.len() < limit {
            matched.push(entry);
        }
        total += 1;
    }
    (matched, total)
}

/// Imported symbols matching `filter`, deduped by (address, name), as one page.
///
/// Covers `ImportedFunction`, `ImportAddress`, `ImportedData` and `External`.
pub fn import_page(
    view: &BinaryView,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
) -> (Vec<SymbolEntry>, usize) {
    let kinds = [
        SymbolType::ImportedFunction,
        SymbolType::ImportAddress,
        SymbolType::ImportedData,
        SymbolType::External,
    ];
    let mut seen: BTreeSet<(u64, String)> = BTreeSet::new();
    let mut entries: Vec<SymbolEntry> = Vec::new();
    for kind in kinds {
        let arr = view.symbols_of_type(kind);
        for sym in arr.iter() {
            let name = symbol_name(&sym);
            if !seen.insert((sym.address(), name.clone())) {
                continue;
            }
            entries.push(symbol_entry(&sym));
        }
    }
    entries.sort_by(|a, b| a.address.cmp(&b.address).then(a.name.cmp(&b.name)));

    let needle = filter.map(str::to_lowercase);
    let mut matched = Vec::new();
    let mut total = 0usize;
    for entry in entries {
        if let Some(needle) = &needle {
            if !entry.name.to_lowercase().contains(needle.as_str()) {
                continue;
            }
        }
        if total >= offset && matched.len() < limit {
            matched.push(entry);
        }
        total += 1;
    }
    (matched, total)
}

/// Read up to `len` bytes at `addr`. Shorter when the range is unmapped.
pub fn read_bytes(view: &BinaryView, addr: u64, len: usize) -> Vec<u8> {
    view.read_vec(addr, len)
}

/// Lowercase hex of `bytes`, no spaces.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Global comment at `addr`. Empty when none is set.
pub fn comment_at(view: &BinaryView, addr: u64) -> String {
    view.comment_at(addr).unwrap_or_default()
}

/// Set (or clear, with an empty string) the global comment at `addr`.
pub fn set_comment_at(view: &BinaryView, addr: u64, comment: &str) {
    view.set_comment_at(addr, comment);
}

/// Native basic blocks of `func`, in start-address order.
pub fn basic_blocks(func: &Function) -> Vec<BasicBlockEntry> {
    let blocks = func.basic_blocks();
    let mut out: Vec<BasicBlockEntry> = blocks
        .iter()
        .map(|block| {
            let start = block.start();
            let end = block.end();
            let outgoing = block.outgoing_edges();
            let mut successors = Vec::new();
            for edge in outgoing.iter() {
                let dest = hex(edge.target.start());
                if !successors.contains(&dest) {
                    successors.push(dest);
                }
            }
            BasicBlockEntry {
                start: hex(start),
                end: hex(end),
                size: end.saturating_sub(start),
                successors,
            }
        })
        .collect();
    out.sort_by(|a, b| a.start.cmp(&b.start));
    out
}

fn address_in_function(view: &BinaryView, func: &Function, addr: u64) -> bool {
    let containing = view.functions_containing(addr);
    containing.iter().any(|f| f.start() == func.start())
}

/// Strings whose address is data-referenced from inside `func`, capped at `cap`.
pub fn referenced_strings(view: &BinaryView, func: &Function, cap: usize) -> Vec<StringEntry> {
    if cap == 0 {
        return Vec::new();
    }
    let all = view.strings();
    let mut refs: Vec<StringReference> = all.iter().collect();
    refs.sort_by_key(|r| r.start);

    let mut out = Vec::new();
    for sref in &refs {
        if out.len() >= cap {
            break;
        }
        let data_refs = view.data_refs_to_addr(sref.start);
        let hit = data_refs
            .iter()
            .any(|r| address_in_function(view, func, r.address));
        if hit {
            out.push(string_entry(view, sref));
        }
    }
    out
}

/// Orientation dossier for one function. Coverage is sampled by the caller.
pub fn analyze_function(
    view: &BinaryView,
    func: &Function,
    analysis_coverage: AnalysisCoverage,
) -> FunctionAnalyze {
    let all_callers = callers(func);
    let all_callees = callees(view, func);
    let caller_count = all_callers.len();
    let callee_count = all_callees.len();
    let callers_truncated = caller_count > ANALYZE_MAX_CALLERS;
    let callees_truncated = callee_count > ANALYZE_MAX_CALLEES;
    FunctionAnalyze {
        name: function_name(func),
        start: hex(func.start()),
        size: function_extent(func),
        basic_blocks: func.basic_blocks().len(),
        callers: all_callers.into_iter().take(ANALYZE_MAX_CALLERS).collect(),
        callees: all_callees.into_iter().take(ANALYZE_MAX_CALLEES).collect(),
        caller_count,
        callee_count,
        callers_truncated,
        callees_truncated,
        referenced_strings: referenced_strings(view, func, ANALYZE_MAX_STRINGS),
        limits: AnalyzeLimits {
            max_callers: ANALYZE_MAX_CALLERS,
            max_callees: ANALYZE_MAX_CALLEES,
            max_strings: ANALYZE_MAX_STRINGS,
        },
        analysis_coverage,
    }
}

fn parsed_type_entry(name: String, declaration: String) -> ParsedTypeEntry {
    ParsedTypeEntry { name, declaration }
}

/// Parse C declarations against the view's default platform.
pub fn parse_declarations(view: &BinaryView, source: &str) -> Result<TypeParseResult, ToolError> {
    let platform = view.default_platform().ok_or_else(|| {
        ToolError::Bn("view has no default platform; cannot parse types".to_owned())
    })?;
    match platform.parse_types_from_source(source, "mcp.h", NO_INCLUDE_DIRS, "") {
        Ok(result) => Ok(TypeParseResult {
            types: result
                .types
                .iter()
                .map(|p| parsed_type_entry(p.name.to_string(), p.ty.to_string()))
                .collect(),
            variables: result
                .variables
                .iter()
                .map(|p| parsed_type_entry(p.name.to_string(), p.ty.to_string()))
                .collect(),
            functions: result
                .functions
                .iter()
                .map(|p| parsed_type_entry(p.name.to_string(), p.ty.to_string()))
                .collect(),
        }),
        Err(e) => Err(ToolError::Bn(e.message)),
    }
}

/// Look up a named type on the view.
pub fn query_type(view: &BinaryView, name: &str) -> Option<TypeQuery> {
    view.type_by_name(name).map(|ty| TypeQuery {
        name: name.to_owned(),
        declaration: ty.to_string(),
    })
}

/// Parse `source` and define a user type named `name`.
///
/// Uses the parsed type whose name matches `name`, or the first parsed type
/// if none matches.
pub fn apply_type(view: &BinaryView, name: &str, source: &str) -> Result<TypeApply, ToolError> {
    let platform = view.default_platform().ok_or_else(|| {
        ToolError::Bn("view has no default platform; cannot parse types".to_owned())
    })?;
    let parsed = platform
        .parse_types_from_source(source, "mcp.h", NO_INCLUDE_DIRS, "")
        .map_err(|e| ToolError::Bn(e.message))?;

    let matched = parsed
        .types
        .iter()
        .chain(parsed.variables.iter())
        .chain(parsed.functions.iter())
        .find(|p| p.name.to_string() == name);
    let ty = if let Some(p) = matched {
        p.ty.clone()
    } else if let Some(p) = parsed
        .types
        .first()
        .or(parsed.variables.first())
        .or(parsed.functions.first())
    {
        p.ty.clone()
    } else {
        return Err(ToolError::Bn(
            "source did not parse any types, variables or functions".to_owned(),
        ));
    };

    view.define_user_type(name, ty.as_ref());
    Ok(TypeApply {
        name: name.to_owned(),
        declaration: ty.to_string(),
        ok: true,
    })
}

/// Write a `.bndb` at `path`.
pub fn create_database(view: &BinaryView, path: &str) -> bool {
    view.file().create_database(path, &SaveSettings::new())
}

/// Save the current view. False when the view is not a database.
pub fn save_view(view: &BinaryView) -> bool {
    view.save()
}

pub fn is_database_backed(view: &BinaryView) -> bool {
    view.file().is_database_backed()
}

fn trace_node(view: &BinaryView, addr: u64, depth: usize) -> TraceDataFlowNode {
    let func = function_name_at(view, addr);
    let kind = if func.is_some() {
        TraceRefKind::Code
    } else {
        TraceRefKind::Data
    };
    TraceDataFlowNode {
        addr: hex(addr),
        func,
        r#type: kind,
        depth,
    }
}

/// One hop as the tracer sees it: `from` → `to`, plus whether it is a code xref.
struct TraceHop {
    from: u64,
    to: u64,
    is_code: bool,
}

fn hops_from(view: &BinaryView, addr: u64) -> Vec<TraceHop> {
    let containing = resolve_function(view, Some(addr), None);
    let mut dests = view.code_refs_from_addr(addr, containing.as_deref());
    dests.sort_unstable();
    let mut hops: Vec<TraceHop> = dests
        .into_iter()
        .map(|dest| TraceHop {
            from: addr,
            to: dest,
            is_code: true,
        })
        .collect();
    let data = view.data_refs_from_addr(addr);
    let mut data_dests: Vec<u64> = data.iter().map(|r| r.address).collect();
    data_dests.sort_unstable();
    hops.extend(data_dests.into_iter().map(|dest| TraceHop {
        from: addr,
        to: dest,
        is_code: false,
    }));
    hops
}

fn hops_to(view: &BinaryView, addr: u64) -> Vec<TraceHop> {
    let code = view.code_refs_to_addr(addr);
    let mut hops: Vec<(u64, TraceHop)> = code
        .iter()
        .map(|r| {
            (
                r.address,
                TraceHop {
                    from: r.address,
                    to: addr,
                    is_code: true,
                },
            )
        })
        .collect();
    let data = view.data_refs_to_addr(addr);
    hops.extend(data.iter().map(|r| {
        (
            r.address,
            TraceHop {
                from: r.address,
                to: addr,
                is_code: false,
            },
        )
    }));
    hops.sort_by_key(|(from, _)| *from);
    hops.into_iter().map(|(_, h)| h).collect()
}

/// Bounded BFS over code and data xrefs. Coverage is sampled by the caller.
pub fn trace_data_flow(
    view: &BinaryView,
    start: u64,
    direction: TraceDirection,
    max_depth: usize,
    analysis_coverage: AnalysisCoverage,
) -> TraceDataFlow {
    let mut visited: HashSet<u64> = HashSet::new();
    visited.insert(start);
    let mut queue: VecDeque<(u64, usize)> = VecDeque::new();
    queue.push_back((start, 0));

    let mut nodes = vec![trace_node(view, start, 0)];
    let mut edges: Vec<TraceDataFlowEdge> = Vec::new();
    let mut depth_reached = 0usize;
    let mut nodes_truncated = false;
    let mut edges_truncated = false;

    while let Some((current, depth)) = queue.pop_front() {
        if depth > depth_reached {
            depth_reached = depth;
        }
        if depth >= max_depth {
            continue;
        }

        let hops = match direction {
            TraceDirection::Forward => hops_from(view, current),
            TraceDirection::Backward => hops_to(view, current),
        };

        for hop in hops {
            if edges.len() >= TRACE_MAX_EDGES {
                edges_truncated = true;
            } else {
                edges.push(TraceDataFlowEdge {
                    from: hex(hop.from),
                    to: hex(hop.to),
                    r#type: if hop.is_code {
                        TraceRefKind::Code
                    } else {
                        TraceRefKind::Data
                    },
                });
            }

            let neighbor = match direction {
                TraceDirection::Forward => hop.to,
                TraceDirection::Backward => hop.from,
            };
            if visited.contains(&neighbor) {
                continue;
            }
            if nodes.len() >= TRACE_MAX_NODES {
                nodes_truncated = true;
                continue;
            }
            visited.insert(neighbor);
            nodes.push(trace_node(view, neighbor, depth + 1));
            queue.push_back((neighbor, depth + 1));
        }
    }

    TraceDataFlow {
        start: hex(start),
        direction,
        depth_reached,
        nodes,
        edges,
        limits: TraceDataFlowLimits {
            max_depth,
            max_nodes: TRACE_MAX_NODES,
            max_edges: TRACE_MAX_EDGES,
            nodes_truncated,
            edges_truncated,
        },
        analysis_coverage,
    }
}

/// A function's own comment, which is not the same object as a comment at an
/// address inside it.
///
/// Binary Ninja keeps both: `Function::comment` is the note on the function,
/// `BinaryView::set_comment_at` is a note on one address. They are exposed as a
/// pair because collapsing them would silently move a caller's text somewhere
/// they cannot read it back from.
pub fn function_comment(func: &Function) -> String {
    func.comment()
}

pub fn set_function_comment(func: &Function, comment: &str) {
    func.set_comment(comment);
}

/// Where a variable lives, in the vocabulary Binary Ninja uses.
fn storage_class(source: VariableSourceType) -> &'static str {
    match source {
        VariableSourceType::StackVariableSourceType => "stack",
        VariableSourceType::RegisterVariableSourceType => "register",
        VariableSourceType::FlagVariableSourceType => "flag",
    }
}

fn variable_entry(named: &NamedVariableWithType) -> VariableEntry {
    VariableEntry {
        name: named.name.clone(),
        r#type: named.ty.contents.to_string(),
        storage_class: storage_class(named.variable.ty).to_owned(),
        storage: named.variable.storage,
        auto_defined: named.auto_defined,
    }
}

/// Every variable analysis recovered for `func`, in a stable order.
///
/// Sorted by storage class then storage slot rather than left in Binary Ninja's
/// order: two reads of the same function have to page identically, and an
/// unstable order turns pagination into a lottery. Stack variables come first
/// because that is the order they appear in pseudocode.
pub fn variables(func: &Function) -> Vec<VariableEntry> {
    let vars = func.variables();
    let mut entries: Vec<(u8, i64, VariableEntry)> = vars
        .iter()
        .map(|named| {
            let rank = match named.variable.ty {
                VariableSourceType::StackVariableSourceType => 0u8,
                VariableSourceType::RegisterVariableSourceType => 1,
                VariableSourceType::FlagVariableSourceType => 2,
            };
            (rank, named.variable.storage, variable_entry(&named))
        })
        .collect();
    entries.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(a.1.cmp(&b.1))
            .then(a.2.name.cmp(&b.2.name))
    });
    entries.into_iter().map(|(_, _, e)| e).collect()
}

/// Parse one C type out of `declaration`, which may be bare (`char *`) or a
/// full declarator (`char *buf`).
///
/// There is no `parse_type_string` in this revision of the Rust API, so the
/// string is wrapped into a declaration and the parsed *variable's* type is
/// taken. The placeholder name cannot collide with anything the caller wrote:
/// if their text already declares a name, the wrapper is a redeclaration and
/// Binary Ninja rejects it, so the bare form is tried first and the wrapped one
/// only as a fallback.
fn parse_one_type(view: &BinaryView, declaration: &str) -> Result<Ref<Type>, ToolError> {
    let platform = view.default_platform().ok_or_else(|| {
        ToolError::Bn("view has no default platform; cannot parse types".to_owned())
    })?;
    let declaration = declaration.trim().trim_end_matches(';').trim();
    if declaration.is_empty() {
        return Err(ToolError::InvalidParams("type is empty".to_owned()));
    }

    let mut last_error = String::new();
    for source in [
        format!("{declaration};"),
        format!("{declaration} __bn_mcp_placeholder;"),
    ] {
        match platform.parse_types_from_source(&source, "mcp.h", NO_INCLUDE_DIRS, "") {
            Ok(parsed) => {
                if let Some(p) = parsed
                    .variables
                    .first()
                    .or(parsed.functions.first())
                    .or(parsed.types.first())
                {
                    return Ok(p.ty.clone());
                }
                last_error = "the declaration parsed but named no type".to_owned();
            }
            Err(e) => last_error = e.message,
        }
    }
    Err(ToolError::InvalidParams(format!(
        "could not parse {declaration:?} as a C type: {last_error}"
    )))
}

/// Find one variable of `func` by the name pseudocode shows.
fn find_variable(func: &Function, name: &str) -> Option<NamedVariableWithType> {
    let vars = func.variables();
    vars.iter().find(|named| named.name == name)
}

/// Rename and/or retype one variable, as a *user* definition.
///
/// `create_user_var` takes name and type together, so both are always written —
/// the side the caller did not ask about is re-supplied from what the variable
/// already has. Passing only a name would otherwise reset the type to whatever
/// the default is, which is a silent downgrade the caller has no way to see in
/// the response.
pub fn set_variable(
    view: &BinaryView,
    func: &Function,
    variable: &str,
    new_name: Option<&str>,
    new_type: Option<&str>,
) -> Result<VariableSet, ToolError> {
    let Some(before) = find_variable(func, variable) else {
        let known: Vec<String> = variables(func).into_iter().map(|v| v.name).collect();
        return Err(ToolError::NotFound(format!(
            "{} has no variable named {variable:?}; it has {}",
            function_name(func),
            if known.is_empty() {
                "none".to_owned()
            } else {
                known.join(", ")
            }
        )));
    };
    let before_entry = variable_entry(&before);

    let name = new_name.unwrap_or(&before.name).trim().to_owned();
    if name.is_empty() {
        return Err(ToolError::InvalidParams("new_name is empty".to_owned()));
    }
    let ty = match new_type {
        Some(text) => parse_one_type(view, text)?,
        None => before.ty.contents.clone(),
    };

    func.create_user_var(&before.variable, ty.as_ref(), &name, false);

    // A user variable is recorded, but the function's variable list is *derived*
    // from analysis — without this the read-back below looks for a name that
    // Binary Ninja has not published yet and the write looks like it failed.
    view.update_analysis_and_wait();

    // Read back rather than assume: `create_user_var` returns nothing, and a
    // write that quietly did not land is worse than one that failed loudly.
    let after = find_variable(func, &name)
        .map(|n| variable_entry(&n))
        .ok_or_else(|| {
            ToolError::Bn(format!(
                "Binary Ninja accepted the variable but {name:?} is not there when read back"
            ))
        })?;
    Ok(VariableSet {
        address: hex(func.start()),
        function: function_name(func),
        before: before_entry,
        after,
        ok: true,
    })
}

/// Give a function a user-defined prototype.
///
/// This is the lever on pseudocode quality that nothing else in this tool
/// surface reaches: argument count, argument types and the return type all come
/// from here, and `il.pseudo_c` re-renders against them.
pub fn set_function_prototype(
    view: &BinaryView,
    func: &Function,
    prototype: &str,
) -> Result<FunctionPrototype, ToolError> {
    let before = func.function_type().to_string();
    let ty = parse_one_type(view, prototype)?;
    func.set_user_type(ty.as_ref());
    // `set_user_type` records the override; `function_type` reports what analysis
    // made of it. Settling between the two is what makes `after` the new
    // signature — read back any earlier it is still the old one, and a prototype
    // that was applied reports as one that was not.
    view.update_analysis_and_wait();
    Ok(FunctionPrototype {
        address: hex(func.start()),
        name: function_name(func),
        before,
        after: func.function_type().to_string(),
        ok: true,
    })
}

/// Rename any symbol at `addr`, function or not.
///
/// `annotation.rename_function` covers the function case and is the one to
/// reach for there; this exists because a data symbol, an import thunk and a
/// label are also things an agent renames after reading, and none of them should
/// need a different tool.
pub fn rename_symbol(
    view: &BinaryView,
    addr: u64,
    new_name: &str,
) -> Result<SymbolRename, ToolError> {
    let Some(existing) = view.symbol_by_address(addr) else {
        return Err(ToolError::NotFound(format!(
            "no symbol at {}; `annotation.rename_symbol` renames an existing symbol rather \
             than creating one",
            hex(addr)
        )));
    };
    let old_name = symbol_name(&existing);
    let symbol_type = symbol_type_name(&existing);

    // Same shape as `rename_function`, and for the same reason: a *user* symbol,
    // with the old one undefined first, or both survive at one address.
    let replacement = Symbol::builder(existing.sym_type(), new_name, addr)
        .full_name(new_name.to_owned())
        .short_name(new_name.to_owned())
        .create();
    view.undefine_user_symbol(&existing);
    view.define_user_symbol(&replacement);

    let observed = view
        .symbol_by_address(addr)
        .map(|s| symbol_name(&s))
        .unwrap_or_default();
    if observed != new_name {
        return Err(ToolError::Bn(format!(
            "Binary Ninja accepted the symbol but reading {} back gave {observed:?}",
            hex(addr)
        )));
    }
    Ok(SymbolRename {
        address: hex(addr),
        old_name,
        new_name: new_name.to_owned(),
        symbol_type,
        ok: true,
    })
}

/// Every data variable the view knows about, in address order.
///
/// Neither `binary.symbols` nor `xref.data_refs_to` answers this question:
/// symbols give a name without a type, and data refs give an address without
/// either. A global table is the entry point into a driver or a firmware image,
/// and reading it needs the type.
pub fn data_var_page(
    view: &BinaryView,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
) -> (Vec<DataVarEntry>, usize) {
    let needle = filter.map(str::to_lowercase);
    let all = view.data_variables();
    let mut vars: Vec<DataVariable> = all.iter().collect();
    vars.sort_by_key(|v| v.address);

    let mut matched = Vec::new();
    let mut total = 0usize;
    for var in &vars {
        let name = view.symbol_by_address(var.address).map(|s| symbol_name(&s));
        let declaration = var.ty.contents.to_string();
        if let Some(needle) = &needle {
            let hit = name
                .as_deref()
                .is_some_and(|n| n.to_lowercase().contains(needle.as_str()))
                || declaration.to_lowercase().contains(needle.as_str());
            if !hit {
                continue;
            }
        }
        if total >= offset && matched.len() < limit {
            matched.push(DataVarEntry {
                address: hex(var.address),
                name,
                r#type: declaration,
                // `width()` is 0 for types with no fixed size; report nothing
                // rather than a zero that reads like a fact.
                size: Some(var.ty.contents.width()).filter(|w| *w > 0),
                auto_discovered: var.auto_discovered,
            });
        }
        total += 1;
    }
    (matched, total)
}

/// Parse a hex byte pattern: `4889e5`, `48 89 e5`, `48:89:e5`.
///
/// One parser for `binary.search` and `patch.bytes`, so a pattern that one
/// accepts is a pattern the other accepts.
pub fn parse_hex_bytes(text: &str) -> Result<Vec<u8>, ToolError> {
    parse_byte_pattern(text)
}

fn parse_byte_pattern(query: &str) -> Result<Vec<u8>, ToolError> {
    let cleaned: String = query
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != ',')
        .collect();
    let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned).to_owned();
    if cleaned.is_empty() {
        return Err(ToolError::InvalidParams("query is empty".to_owned()));
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err(ToolError::InvalidParams(format!(
            "{query:?} has an odd number of hex digits; a byte pattern needs two per byte"
        )));
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|_| {
                ToolError::InvalidParams(format!(
                    "{:?} in {query:?} is not a hex byte",
                    &cleaned[i..i + 2]
                ))
            })
        })
        .collect()
}

/// Scan the view for `query`, stopping at `limit` hits.
///
/// Binary Ninja's find API answers "where is the next one", so this walks it.
/// Each hit restarts the scan one byte later — not one *match* later — because a
/// pattern may overlap itself and skipping the whole match would drop the
/// second half of `aaaa` searched for `aa`.
pub fn search(
    view: &BinaryView,
    kind: SearchKind,
    query: &str,
    limit: usize,
    analysis_coverage: AnalysisCoverage,
) -> Result<SearchResult, ToolError> {
    let start = view.start();
    let end = view.end();
    let mut hits = Vec::new();
    let mut cursor = start;

    let normalized = match kind {
        SearchKind::Bytes => {
            let bytes = parse_byte_pattern(query)?;
            bytes_to_hex(&bytes)
        }
        SearchKind::Text | SearchKind::Constant => query.trim().to_owned(),
    };
    let constant =
        if matches!(kind, SearchKind::Constant) {
            Some(vibrev_kit::parse_int(normalized.trim()).map_err(|e| {
                ToolError::InvalidParams(format!("{query:?} is not an integer: {e}"))
            })? as u64)
        } else {
            None
        };
    let buffer = match kind {
        SearchKind::Bytes => Some(DataBuffer::new(&parse_byte_pattern(query)?)),
        _ => None,
    };
    if matches!(kind, SearchKind::Text) && normalized.is_empty() {
        return Err(ToolError::InvalidParams("query is empty".to_owned()));
    }

    let mut truncated = false;
    while cursor < end {
        let found = match kind {
            SearchKind::Bytes => {
                view.find_next_data(cursor, end, buffer.as_ref().expect("bytes has a buffer"))
            }
            SearchKind::Text => {
                view.find_next_text(cursor, end, &normalized, FunctionViewType::Normal)
            }
            SearchKind::Constant => view.find_next_constant(
                cursor,
                end,
                constant.expect("constant was parsed"),
                FunctionViewType::Normal,
            ),
        };
        let Some(addr) = found else { break };
        hits.push(SearchHit {
            address: hex(addr),
            function: function_name_at(view, addr),
        });
        if hits.len() >= limit {
            truncated = true;
            break;
        }
        cursor = addr.saturating_add(1);
    }

    Ok(SearchResult {
        kind,
        query: normalized,
        start: hex(start),
        end: hex(end),
        hits,
        truncated,
        analysis_coverage,
    })
}
