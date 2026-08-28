# Tool surface

How this engine decides which tools to ship. The two existing Binary Ninja MCP
servers are the input; they are not the target.

Sources:

* `binary_ninja_mcp` — GUI plugin + HTTP + two bridges. **56** flat-named tools.
* `binary-ninja-headless-mcp` — headless, **181** tools in 36 `group.verb` groups.
* ida-pro-mcp design: batch-first, composites, no implicit current object.
* The 181-tool headless server is the cautionary tale: C API coverage is not a product.
* IDA engine counterparts, for the composite tools that have to feel the same.

## What we keep

| From | What | Why |
|---|---|---|
| headless | `group.verb` | Matches Binary Ninja's own vocabulary. |
| headless | `health.ping` with no session | Connectivity check must not cost a Binary Ninja init. |
| headless | `xref.code_refs_{to,from}` as primitives | Address-level refs and function-level callers are different questions. |
| headless | `memory.read` 64 KB hard cap | When that tool lands. |
| headless | Pagination on every list | Firmware images exist. |
| headless | `binary.data_vars` | A typed global is the way into a driver. Symbols give a name without a type; data refs give an address without either. |
| headless | `binary.search_text` + `search.*` | Collapsed into one `binary.search` with a `kind`. Same scan, three questions. |
| headless | `function.variables` | See "What the measurements decided". |
| headless | `patch.*` | See "What the measurements decided". |
| GUI plugin | One identifier that is a name *or* an address | `main` and `0x401000` both work; agents type both. |
| GUI plugin | Comments / rename as the write path | That is what an agent actually does after reading. |
| GUI plugin | Function comments *and* address comments | Binary Ninja keeps two objects; collapsing them puts a caller's text where they cannot read it back. |
| GUI plugin | `set_function_prototype` / `set_local_variable_type` | The only lever this surface has on pseudocode quality. |
| GUI plugin | `patch_bytes` | Kept as `patch.bytes`, alongside the structured patches it is the fallback for. |
| GUI plugin | Strings with an optional filter | They split this into three tools; we keep one. |
| ida-pro-mcp | `*.survey` / `*.analyze` composites | One call instead of six probes. |
| measured here | `analysis_coverage` on every aggregate | Unconverged Pseudo C was observed, not theorized. |

## What we refuse

| From | What | Why |
|---|---|---|
| headless | 181 tools, 36 groups | Coverage of the C API is not a product. |
| headless | `il.function` / SSA / `il.rewrite.*` | #7731 is rewriting those bindings. We take rendered text. |
| headless | `binary.get_function_disassembly_at` *and* `disasm.function` | Same question, two names. We keep `disasm.function`. |
| headless | `binary.get_function_at` / `binary.functions_at` / `function_at` | Resolve is an argument, not a tool. |
| headless | `analysis.update` / `analysis.abort` / `analysis.set_hold` | Loads already wait. Incremental analysis is #8165. |
| headless | `workflow` / `project` / `type_archive` / `plugin_repo` / `external` | Binary Ninja product features over RPC, not reverse-engineering questions. |
| headless | `undo.begin` / `commit` / `revert` / `undo` / `redo` | Five tools exposing Binary Ninja's transaction model. `patch.revert` is the one question anyone has, and `RevertUndoActions(id)` is a trap — see below. |
| headless | `patch.convert_to_nop` *and* `patch.never_branch` | One core call. `BNNeverBranch` does not exist; Python's `never_branch` forwards to `BNConvertToNop`. We ship `patch.nop`. |
| headless | `memory.write` / `insert` / `remove` | `patch.bytes` is the same write under the name that says what it is for. Insert and remove change every address after them. |
| GUI plugin | Implicit current binary (`select_binary`) | The supervisor holds several views; there is no current one. |
| GUI plugin | `list_all_strings` | Dumps the table. Pagination exists so this does not. |
| GUI plugin | `list_strings` + `list_strings_filter` | Same tool, one of them missing a flag. |
| GUI plugin | `list_exports` / `list_namespaces` as separate tools | `binary.symbols` takes a `kind`. Resolve is an argument, not a tool — the same rule as above. |
| GUI plugin | Walking `func.hlil` for decompile | That is the #7731 surface. `il.pseudo_c` uses `LinearViewObject`. |
| both | Returning only a string, or a compact summary that is not the payload | `Rendered<T>`: `content[0].text` is the readable form of the same structured value. |

## What the measurements decided

Four of the decisions above look obvious from a distance and are not. In each
case the evidence is worth more than the decision it produced.

**`script.python`** reads as full RCE as a default tool. The threat is real but
it is not the *tool's*: under `--mode stdio` there is no listening face, so the
only way to reach a tool is to be the process that spawned it, and a caller who
can spawn `bn-headless-mcp` can already run anything. A listener changes that,
and `serve` now listens by default — so the answer there is a startup banner
naming the exposure and `--exclude-tools script.python` as the way to say no; see
the README's trust-boundary section. Neither route makes a permission layer
around this one tool the right shape.

The value on the other side is large. Binary Ninja's Python API is where every
capability this surface does *not* wrap already lives, and [measured] it runs
**in this worker's process against this worker's view**: `bv` is the loaded
`BinaryView`, a rename from Python is visible to `binary.functions` immediately,
and the round trip is 0.09 s because nothing is re-analyzed. A shell-out to
`bnpython3` would have paid the 3.5–10 s load again and written to a different
view.

The hazards are recorded on the tool itself: it is annotated
`destructive: true, open_world: true`, and the one thing a script must not do —
write to file descriptor 1, which is this process's MCP channel — is in its
description.

**`patch.*`** is Binary Ninja's signature capability, and the only thing that
ever stood against shipping it was "nothing is written to disk".
`database.create_bndb` has always been the answer to "where does the change go",
and `database.export_binary` is the other half, writing the patched bytes out as
a runnable file. Both are asserted end to end: the suite patches a byte, saves
each way, opens the result in a **second worker process** and reads the byte back
there. A patch tool that reports success and loses the change on close would be
worse than no patch tool.

Two things came out of building it that the reference implementations get wrong.
`binary-ninja-headless-mcp` ships `patch.convert_to_nop` and `patch.never_branch`
as separate tools, but there is no `BNNeverBranch` in the header and Python's
`never_branch` forwards to `BNConvertToNop` — one call, so one tool. And the
*availability* query is not symmetric with the action:
`BNIsNeverBranchPatchAvailable` asks "is this a branch I could neutralize", which
[measured] answers `false` for `push rbp` — an instruction `BNConvertToNop` then
NOPs successfully. Reporting that as `can_nop` would have been a plausible wrong
answer, which is the worst kind, so `can_nop` comes from whether anything decodes
and `can_never_branch` keeps the branch question.

**`undo`** stays off the surface as a transaction model, but one question needed
answering: a patch is a destructive, in-session, irreversible write, and getting
the address wrong otherwise leaves no way back except closing the view and losing
every annotation with it. So there is exactly one tool, `patch.revert`, and its
shape is entirely dictated by what the undo stack actually does:

* **It is per-file and strictly LIFO over every edit.** A rename lands on it too
  — and costs *two* entries, because `rename_function` undefines the old symbol
  and defines the new one. So a revert tool that just calls `BNUndo` answers
  "revert my patch" by taking back a rename. `patch.revert` reads the top entry
  first, through `BNUndoEntryGetActions`, and reverts only if every action in it
  is a data write. Otherwise it refuses and says what is on top.
* **`BNRevertUndoActions(id)` is not a targeted revert.** It looks like the
  obvious way to undo one specific patch. [Measured] on a transaction that
  already has a newer one above it, it is a **silent no-op** — nothing undone, no
  error, no return value. `UndoEntry` does not even carry the id, so that
  feature cannot accidentally get built on it.
* **`BNCanUndo` lies right after a patch.** [Measured] it answers `false`, and
  `BNGetUndoEntries` is empty, for about 50 ms after an unbracketed write — while
  `BNUndo` would have worked the whole time. Nothing gates on it. Instead every
  patch runs inside an explicit `BeginUndoActions`/`CommitUndoActions` bracket,
  which makes the entry appear the instant commit returns *and* collapses
  `patch.assemble`'s encoding-plus-padding into one entry, so one revert takes
  back one patch.

**`function.variables`** earns its schema through one workflow, and that workflow
is retyping: `il.pseudo_c` renders a variable's type at every use, so naming a
`void *` as `struct sockaddr *` changes the whole function's readability, and
nothing else in this surface reaches that. `function.variables` is the tool that
tells you which name to pass to `function.set_variable`. The e2e suite asserts
the property rather than the return code — pseudocode before and after a
prototype must differ.

## Naming

Worker tools are `group.verb`. Supervisor session tools are the same shape
(`session.open`, `health.ping`). A `target` parameter is always "name or any
address inside the function". Addresses in responses are hex strings.

Layering:

* `xref.*` answers *an address* — one instruction, one data slot.
* `function.*` answers *a function* — callers, callees, variables, analyze.
* `binary.*` answers *the view* — lists, the search, and the survey.
* `annotation.*` and `type.*` *write* — names and comments in the first,
  declarations in the second.
* `il.pseudo_c` / `disasm.function` answer *one function as text*, one field, so
  they pipe.
* `patch.*` *changes the bytes*, and `database.*` is the only thing that makes
  that survive the process.
* `script.*` is the escape hatch — everything the groups above do not wrap.

`function.callers` is not a synonym of `xref.code_refs_to`. The xref names the
referencing instruction; the function tool names the calling function, once.

## Catalog

Shipped (worker + supervisor):

| Tool | Kind | Notes |
|---|---|---|
| `session.open` / `list` / `close` | supervisor | One worker process per view |
| `health.ping` | supervisor | No Binary Ninja, no `view` |
| `binary.segments` | list | Loader ranges. `contains_code` is a loader flag, not a fact |
| `binary.sections` | list | Named ranges |
| `binary.functions` | paged list | `total` is the whole match set |
| `binary.strings` | paged list | Optional substring filter. Encoding preserved |
| `binary.symbols` | paged list | Name, address, `SymbolType`. `kind` restricts to one type — this is where "list the exports" lives |
| `binary.imports` | paged list | ImportedFunction + ImportAddress + ImportedData + External |
| `binary.data_vars` | paged list | Address, name, type, width. `filter` matches name *or* type |
| `binary.search` | scan | `kind`: `bytes` (hex pattern), `text` (rendered disassembly), `constant`. Resumes one byte past a hit, so overlaps are all reported |
| `binary.survey` | composite | Aligned with IDA `survey_binary` |
| `il.pseudo_c` | text | `LinearViewObject` language representation |
| `disasm.function` | text | Same cursor, linear disassembly. Field is `listing` |
| `disasm.range` | text | Address-range listing. Field is `listing` |
| `xref.code_refs_to` / `code_refs_from` | paged | Address-level code references |
| `xref.data_refs_to` / `data_refs_from` | paged | Address-level data references |
| `function.callers` / `callees` | paged | Calling / called *functions*, deduped |
| `function.basic_blocks` | paged | CFG nodes + successor starts |
| `function.variables` | paged | The names `il.pseudo_c` prints, with types and storage |
| `function.set_variable` | write | Rename and/or retype. The omitted side is re-supplied, so a rename never resets the type |
| `function.analyze` | composite | Aligned with IDA `analyze_function` (no decompile) |
| `memory.read` | bytes | Hex dump, 64 KB hard cap |
| `annotation.rename_function` | write | User symbol, in-memory only |
| `annotation.rename_symbol` | write | Any symbol at an address — data, thunk, label |
| `annotation.get_comment` / `set_comment` | read/write | Comments at an *address* |
| `annotation.get_function_comment` / `set_function_comment` | read/write | The comment on a *function*. A different object; the e2e suite asserts they do not read each other |
| `type.parse_declarations` / `query` / `apply` | types | Parse C, look up, define user type |
| `type.set_function_prototype` | write | Put a signature on a function. Re-runs analysis and reads back what Binary Ninja settled on |
| `patch.available` | query | What Binary Ninja will accept here, asked instead of attempted |
| `patch.nop` | write | Also "never branch" — one core call, one tool |
| `patch.always_branch` / `invert_branch` | write | Binary Ninja picks the encoding and pads it |
| `patch.skip_and_return` | write | Neuter a call, leave a value in the return register |
| `patch.assemble` | write | Pads a short encoding with NOPs; refuses a long one unless told |
| `patch.bytes` | write | Raw hex. The one patch tool that will leave half an instruction |
| `patch.revert` | write | Undoes the newest patch, and refuses if the newest change is not one |
| `database.create_bndb` / `save` | persist | Write a `.bndb`; `save` no-ops on a raw view |
| `database.export_binary` | persist | The patched binary itself, not the analysis |
| `analyze.trace_data_flow` | composite | Bounded xref BFS, aligned with IDA |
| `script.python` | script | Binary Ninja's Python, in this process, against this view. `result` comes back as JSON; `print()` is captured |
| `script.reset` | script | Clear the console's namespace without restarting the interpreter |

Not on the list until someone has a workflow that the tools above cannot serve:
IL AST, SSA def-use, IL rewrite, loader rebase, external libraries, collaboration,
debug info parsers, `binja.call`, `list_namespaces`, `list_classes`. Most of them
are one `script.python` call away, which is the point — a tool has to earn a
schema, not just be reachable.
