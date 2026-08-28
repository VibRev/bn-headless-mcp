# bn-headless-mcp

Binary Ninja as a complete MCP server, plus a command line built from the same
tool definitions.

You point your client straight at this binary. Nothing sits between your agent
and Binary Ninja — no plugin inside a GUI, no HTTP bridge, no second process
translating one protocol into another.

```
$ bn-headless-mcp tool binary survey --input /bin/cat    # one-shot CLI
$ bn-headless-mcp serve                                  # MCP over HTTP (the default)
$ bn-headless-mcp serve --mode stdio                     # MCP over stdio
```

---

## The tool surface

**51 tools: 47 on the worker, 4 on the supervisor.** The catalog, and the reasons
we did not copy the two existing Binary Ninja MCP servers, live in
[`docs/TOOLS.md`](docs/TOOLS.md).

| Tool | |
|---|---|
| `session.open` / `list` / `close` | One worker process per binary |
| `health.ping` | Supervisor liveness — no Binary Ninja, no `view` |
| `binary.segments` / `sections` / `symbols` / `imports` | Lists. `symbols` takes a `kind` |
| `binary.functions` / `strings` / `data_vars` | Paged, with a real `total` and `next_offset` |
| `binary.search` | Bytes, disassembly text, or a constant |
| `binary.survey` | One call's worth of orientation, aligned with IDA's `survey_binary` |
| `il.pseudo_c` / `disasm.function` / `disasm.range` | Text that pipes |
| `xref.code_refs_*` / `data_refs_*` | Address-level references |
| `function.callers` / `callees` / `basic_blocks` / `analyze` | Function-level |
| `function.variables` / `set_variable` | The names pseudocode prints; rename and retype |
| `memory.read` | Hex dump, 64 KB cap |
| `annotation.rename_function` / `rename_symbol` | In-memory writes |
| `annotation.*_comment` / `*_function_comment` | Comments at an address, and on a function |
| `type.parse_declarations` / `query` / `apply` | C types |
| `type.set_function_prototype` | The lever on pseudocode quality |
| `patch.available` | What Binary Ninja will accept at an address |
| `patch.nop` / `always_branch` / `invert_branch` / `skip_and_return` | Structured patches |
| `patch.assemble` / `bytes` | Assemble and write, or write raw hex |
| `patch.revert` | Undo the last patch — and refuse if the last change was not one |
| `database.create_bndb` / `save` | Persist the analysis *and* the patches |
| `database.export_binary` | Write the patched binary out |
| `analyze.trace_data_flow` | Bounded xref BFS, aligned with IDA |
| `script.python` / `reset` | Binary Ninja's Python, in this process, against this view |

We do not ship 181 wrappers. What we refuse, and what we took from where, is in
[`docs/TOOLS.md`](docs/TOOLS.md).

Alongside the tools, the supervisor answers the MCP task verbs — `tasks/get`,
`tasks/update`, `tasks/cancel`. Those are protocol rather than tools, and the
tool count does not move because of them; see
[Work that takes a while](#work-that-takes-a-while).

### Where changes go

Every write a tool makes — a rename, a comment, a patch — lands in the in-memory
view and nowhere else. Two tools put it on disk, and they are not
interchangeable:

| | What it saves | What you get |
|---|---|---|
| `database.create_bndb` | Analysis, names, comments **and** patches | A `.bndb` to reopen and keep working in |
| `database.export_binary` | The bytes | The input format with the patches applied — the thing you run |

Closing a view without one of them loses the lot. Both round trips are asserted
end to end: the suite patches a byte, saves each way, opens the result in a
**second worker process**, and reads the byte back there. A patch tool that
reports success and drops the change on close would be worse than no patch tool.

```console
$ bn-headless-mcp tool patch available 0x4025f6 --input ./target.bin
$ bn-headless-mcp tool patch invert_branch 0x4025f6 --input ./target.bin
$ bn-headless-mcp tool patch assemble 0x4025f6 'nop' --input ./target.bin
```

`patch.available` asks before you try: Binary Ninja refuses an inapplicable patch
by writing nothing and returning false, which a caller cannot tell from a
successful no-op, so the refusal comes back as an error naming what *is*
available there. `patch.revert` takes back the newest patch and declines if the
newest change was something else — the undo stack is per-file and
last-in-first-out over *every* edit, so a revert that just called `BNUndo` would
answer "revert my patch" by taking back your last rename. The per-tool reasoning,
including why there is no `patch.never_branch`, is in
[`docs/TOOLS.md`](docs/TOOLS.md).

### Python

`script.python` runs against the `BinaryView` this worker already holds — `bv` is
bound to it, so there is nothing to load and a write is visible to the other
tools immediately.

```console
$ bn-headless-mcp tool script python --input /bin/cat '
import collections
counts = collections.Counter(len(list(f.basic_blocks)) for f in bv.functions)
print("distinct block counts:", len(counts))
result = {"functions": len(list(bv.functions)), "top": counts.most_common(3)}'
```

Assign to `result` to return a value; it comes back as JSON when it is
serializable and as `repr()` when it is not. `print()` is captured into
`stdout`. The interpreter is one long-lived console, so names persist between
calls — `script.reset` clears them.

> **This process speaks MCP over its real stdout.** `print()` is safe: Binary
> Ninja replaces `sys.stdout` with a writer that feeds the output listener, and
> nothing reaches file descriptor 1. `os.write(1, ...)` and `sys.__stdout__` are
> not safe — they write into the JSON-RPC stream and end the session. There is
> no way to prevent that from inside the process.

There is no permission layer around this tool and it is advertised by default;
see [The trust boundary](#the-trust-boundary) for why, and for how to say no.

### Long answers

Per-tool limits govern how much a tool *intends* to return. They do not cover a
single oversized value: `il.pseudo_c` on a ten-thousand-line function carries no
`limit` and would go straight into a client's context.

So the worker is wrapped in an output net. Past **50,000 characters** an answer
arrives as a shape-preserving preview plus a hint, the full value is written to a
private file, and `_meta.vibrev.download_url` carries a `file://` URL to it. The
threshold is a ceiling, not a floor — an ordinary page of `binary.functions`
never touches it.

The net sits on the worker rather than the supervisor for two reasons that both
matter: the supervisor forwards a worker's result verbatim and trimming there
would break that guarantee, and the worker is where the big answer is produced,
so ten megabytes of pseudocode never cross the pipe between the two processes at
all. The one-shot CLI is deliberately unaffected — it writes to a pipe, not into
a context window, and truncating there answers a question nobody asked.

A spilled file lives as long as the worker, which is as long as the view: closing
a view takes its outputs with it. A worker that is `SIGKILL`ed runs no destructor
and leaves its `0700` directory behind in `/tmp`.

### Work that takes a while

Two calls are worth a handle rather than a wait: `session.open`, which pays a
full load and analysis pass, and `script.python`, which will sit there for up to
600 seconds if you ask it to. Pass `background: true` and the response becomes a
task — poll it with `tasks/get`, stop it with `tasks/cancel`. The advertised poll
interval is 500 ms, because the work here is seconds-scale.

The settled payload is the worker's own result, serialized once. The end-to-end
suite asserts it is byte for byte what the blocking call returns, so backgrounding
a call changes when you get the answer and nothing about the answer.

There is no `task_status` tool. A hand-rolled polling verb next to the one MCP
already defines is two ways to ask the same question, and a client that cannot
hold a protocol handle loses nothing by omitting `background` — that is the
answer it gets today. Asking for `background: true` from such a client is refused
in as many words rather than silently ignored.

Two things about cancelling. Cancelling a `script.python` discards its output but
does not undo what it already changed. Cancelling a `session.open` closes the
view it opened only if nothing has picked that view up in the meantime — a
concurrent, blocking `session.open` on the same path is handed the same view, and
cancelling the background one must not pull it out from under them.

---

## Building

**There are no downloadable releases and there will not be any soon.** This
binary links `libbinaryninjacore` and is built against the Binary Ninja API at a
specific commit; a build produced on one machine is tied to the Binary Ninja
install it was built against. Everyone builds from source. The same is true of
`ida-headless-mcp` for the same reason.

### What you need

* **Binary Ninja, Commercial or Ultimate.** Headless operation is not available
  on Personal. Developed and tested against **5.3.9757**.
* **Rust 1.95 or newer** — the MSRV comes from `vibrev-kit`, not from the
  Binary Ninja API (whose own is 1.91.1). This crate stays edition 2021.
* **clang** — `binaryninjacore-sys` runs bindgen.
* **git** — the API is fetched as a git dependency, ~100 MB of clone plus
  submodules on first build.

### Build

```bash
export BINARYNINJADIR=~/binaryninja          # your Binary Ninja install directory
cargo build --release
```

`BINARYNINJADIR` is a *build-time* variable: `binaryninjacore-sys` reads it to
find the core, and `build.rs` bakes that directory into the binary's rpath. The
result runs without `LD_LIBRARY_PATH` set.

### Run

```bash
export BN_LICENSE="$(cat ~/bn-license.txt)"  # or put license.dat in the BN user directory
./target/release/bn-headless-mcp doctor
```

`doctor` reports the pinned API commit, whether a license can be found and where
it came from. It initializes nothing, so it still answers on a machine that could
not actually open a binary.

> On Linux, Binary Ninja ships `libbinaryninjacore.so.1` and no unversioned
> `.so`. `binaryninjacore-sys` creates the symlink itself, which means the build
> writes into `BINARYNINJADIR`.

---

## Running it

**One server command, two transports.** `serve` is what a bare invocation runs,
and it speaks **HTTP unless you ask for stdio**.

```bash
bn-headless-mcp                                    # serve, HTTP, 127.0.0.1:8765
bn-headless-mcp serve --mode http --allow-origin http://localhost
bn-headless-mcp serve --mode stdio                 # your client spawns this
```

**HTTP** is one route, `/mcp`, bound to `127.0.0.1:8765` by default. Every
request carries a bearer token, and the `Origin` and `Host` checks run alongside
it. The token comes from `$VIBREV_HOME/token`, falling back to `~/.vibrev/token`,
created `0600` on first use and reused afterwards; `--token-file` points
elsewhere.

There is no switch that turns authentication off, and that is not a promise made
in documentation: the transport this is built on has no such parameter, so the
code that would honour it cannot be written.

**stdio** has no listener at all. Your client spawns this process and talks over
the pipe; the process spawns a worker per binary you open. Spell the mode out in
the client config — an entry with no args gets the HTTP default, which reads as a
hang rather than as an error, because the pipe it is waiting on is never written
to.

```json
{ "command": "bn-headless-mcp", "args": ["serve", "--mode", "stdio"] }
```

The listener flags live on `serve` in both modes, so under `--mode stdio` they
parse and cannot be honoured. They are **refused rather than ignored**:

```console
$ bn-headless-mcp serve --mode stdio --bind 0.0.0.0:9000
Error: --bind has no meaning with --mode stdio (there is no listener to
configure); drop it or run --mode http
```

Only a flag you actually typed counts. The names come from the transport's own
argument set rather than a list kept here, so a listener flag added upstream
cannot slip through by being unknown to this engine.

**`bn-headless-mcp tool <group> <verb>` — one shot.** Loads the binary, answers,
exits. Same definitions, same bytes as the MCP call; see
[Two front ends, one definition](#two-front-ends-one-definition).

### Narrowing the surface

Four global flags, honoured everywhere above:

| | |
|---|---|
| `--read-only` | Drops every tool annotated as a write. 32 tools remain; `patch.available` survives because it only asks |
| `--toolsets <group>` | Whole `group.verb` families, case-folded. `--toolsets patch` gives you the patch group |
| `--tools <name>` | Individual tools by name |
| `--exclude-tools <name>` | Individual tools removed. This is how you say no to `script.python` |

An active policy says so on stderr at startup, counted by running the catalog
through the policy rather than by tracking a number next to it, so the log cannot
disagree with what the client is given.

**The four session primitives survive every narrowing.** `session.open` /
`close` / `list` and `health.ping` are exempt from `--read-only` and from
toolset selection, and only a by-name `--exclude-tools` removes them. This is not
tidiness: the supervisor injects a required `view` parameter into every analysis
tool and `session.open` is the only thing that hands one out, so dropping it
leaves a server whose every remaining tool answers "needs `view`" with no way to
get one. It was found by running the real server — `--toolsets patch` gave eight
patch tools and zero callable ones.

**The default advertises everything**, `script.python` included. Withholding a
capability the engine plainly ships means an operator discovers it through "why
does this not work", and `--exclude-tools` is already the way to say no.

---

## The trust boundary

Under `--mode stdio` there is no listening face. The only way to reach a tool is
to be the process that spawned this one, and that process can already run
anything — the trust boundary is process creation, not tool dispatch, and a
permission layer around a single tool would be a door in an open field.

**That argument does not survive a listener, and the listener is now the
default.** Whoever holds the token reaches the tools, whether or not they could
have spawned this process. The answer is not to hide tools; it is to say, **at
every start**, what this port reaches:

```
   exposure     : a caller holding the token can open any file on this host
                  for analysis (reading arbitrary files is what this tool
                  does) and can write analysed or patched copies back to
                  disk and can execute arbitrary code — script.python runs
                  caller-supplied Python inside a worker; --exclude-tools
                  script.python removes it
```

That banner is read off the **live policy**, not hard-coded. An operator who
passed `--exclude-tools script.python` is not told their listener runs arbitrary
code, and one who passed `--read-only` is not told it writes to disk. Under
`--mode stdio` it does not print at all — there is no port to describe.

---

## Version pinning

`Cargo.toml` pins both `binaryninja` and `binaryninjacore-sys` to

```
aa25bfcfd36532ec3850558a58444df7727e297b
```

**Why that commit.** It is the one named in `api_REVISION.txt` inside the Binary
Ninja 5.3.9757 install — that file is how the product records which API commit
its core was built from. Pinning it makes the headers we compile against and the
core we link against the same revision. That is the only way to get the
compile-time API and the link-time core from one source.

**Why pin at all, and why a commit rather than a tag.** The Rust API is not on
crates.io (the `binaryninja` name there is a 12-line placeholder at 0.0.1), and
the repository has no `master` or `stable` branch — only `dev`. There is nothing
to track that is not a moving target. A tag would be closer to the product
version but still not exact; `api_REVISION.txt` is exact.

**What moving the pin costs.** Not theoretical. Three signature changes were
already measured between the documentation on `dev` and what 5.3.9757 actually
exposes:

| | Documented | 5.3.9757 |
|---|---|---|
| `Session::load` | `Result<Ref<BinaryView>, _>` | `Option<Ref<BinaryView>>` |
| Symbol name | `.name()` | `.full_name()` / `.short_name()` / `.raw_name()` |
| `BnString` | String-like | derefs to `CStr`; no `Display`, needs `.to_string_lossy()` |

**The mitigation.** Every Binary Ninja call lives in `src/bn/`. Moving the pin is
a diff against that directory, not against the engine.
`src/bn/mod.rs::PINNED_API_REVISION` duplicates the hash so `doctor` can print
it, and a unit test fails if the two ever disagree.

### Upstream issues this engine works around

| Issue | What happens | What we do |
|---|---|---|
| **#6660** | Dropping the last `Session` calls `BNShutdown`; the next `Session::new()` never returns. Reported as a segfault, reproduces here as a **hang** — worse, because there is no core dump, only a request that never answers. | One `Session` per process, never shut down. Closing a view kills the process; that is also the only thing that returns the memory. |
| **#8165** | Analysis can wedge when driven incrementally. | Every load uses `update_analysis_and_wait = true`. |
| **#7731** | MLIL/HLIL bindings are about to be rewritten. | Pseudocode comes from `LinearViewObject::language_representation` — rendered text from the core — instead of walking the HLIL AST. Very little of our code sits on top of the churn. |
| **`load_with_options(.., None)` never succeeds** | [Measured, this commit] The `None` branch builds its default options through `Metadata::new_of_type(KeyValueDataType).get_json_string()`, and that method answers `None` for every type except `StringDataType` (`src/metadata.rs:170`). The `.ok()?` returns before the core is called, so the function fails for *every* input, not just unusual ones. Probed on `/bin/cat`: `load()` ok, `None` fails, `Some("{}")` ok. | Always pass `Some(json)`. |

---

## How it is put together

```
client ──HTTP or stdio──▶ bn-headless-mcp serve      (supervisor: session table, no Binary Ninja)
                                │
                                ├──stdio MCP──▶ worker --input a.bin   (Session + BinaryView)
                                └──stdio MCP──▶ worker --input b.so
```

**One worker process per open binary, no pooling.** Not a performance choice.
Binary Ninja cannot be re-initialized in a process (#6660), so there is no
in-process way to close a view and get the memory back. A process makes "close"
mean `kill`, which does work. The price is a full Binary Ninja startup and
analysis per open binary — [measured] on a release build, `session.open` to first
answer:

| | |
|---|---|
| `/bin/cat` (39 KB, 110 functions) | 3.5 s |
| `/bin/ls` (137 KB) | 9.4 s |
| `/bin/grep` (170 KB) | 10.3 s |
| `doctor` (no Binary Ninja init) | 0.01 s |

Most of that is analysis, not startup, and it is paid once: subsequent calls
against an open view answer in milliseconds. `session.open` on a path that is
already open returns the existing handle rather than paying again.

**Workers do not outlive the supervisor.** Two mechanisms, because one of them
does not cover the interesting case. `kill_on_drop` handles an orderly exit —
but a supervisor killed with `SIGKILL` runs no destructors, so the workers'
stdin reaching EOF is what ends them. [Measured] `SIGKILL` the supervisor with
two workers open: both gone within two seconds.

**Four concurrent calls per view.** [Measured] hammering a shared `BinaryView`
from 8 threads for 20 s: no crash, no deadlock, and 8,652 cross-thread
observations of the same function agreed exactly. But the speedup was 3.83× on a
16-core machine — the
core is largely serial internally. Beyond four, extra concurrency only takes CPU
away from analysis, which makes convergence *slower*. Different views are
independent; no global lock inside a worker is needed.

**Answers wait for analysis.** Pseudocode is not deterministic before analysis
converges: [Measured] the same function rendered 1876 characters and then 1836.
So loads use `update_analysis_and_wait`,
reads settle analysis before they read, and pseudocode rendering sets
`WaitForIL`. This is the source-level fix; `analysis_coverage` below is the
reporting half. [Measured] eight concurrent `il.pseudo_c` calls on one view
returned eight identical renderings.

**The supervisor forwards results verbatim.** It does not rebuild `content` from
the worker's structured payload. That matters because clients connect to the
supervisor, so a re-rendering step there would quietly break the guarantee in the
next section on the only surface anyone actually uses.

---

## Two front ends, one definition

Each tool is written once, as a `#[vibrev_tool]` in `src/server/mod.rs`. The same
macro derives the MCP tool and the clap subcommand in one compilation unit, so
they cannot drift, and a tool that forgets `title` or `annotations` does not
compile.

`tests/two_paths.rs` asserts the stronger property: for every tool, the
`content[0].text` of `tools/call` is **byte for byte** what
`bn-headless-mcp tool …` prints — through the worker *and* through the
supervisor. It holds by construction rather than by agreement: both paths run the
same function body through the same `IntoCallToolResult`, so there is one
producer of those bytes, not two that match.

Tools live under `tool`, management commands at the root:

```
bn-headless-mcp serve | worker | doctor                   # management
bn-headless-mcp tool binary functions --limit 5 --input /bin/cat
bn-headless-mcp tool il pseudo_c main --input /bin/cat
bn-headless-mcp tool --help                               # every tool
```

`--json` prints the structured payload instead of the rendered text. Note what
that costs on a decompiler: the default prints source you can pipe into a file,
`--json` prints the same source escaped into one JSON string. Opting in is fine;
having it as the *only* option is the trap: the model then sees escaped JSON
instead of source.

> **A rough edge worth knowing.** The shared renderer prints a list as an aligned
> table only when every other key is bookkeeping (`total`, `offset`, `limit`, …).
> `analysis_coverage` is not on that list, so every tool that carries coverage
> falls back to pretty-printed JSON instead of a table. Nothing is wrong with the
> output and both front ends still agree byte for byte, but the two conventions
> currently cancel each other out. `session.list`, which has no coverage field,
> shows what the table form looks like.

---

## Analysis completeness

Every tool that reports a total, a full list or a cross-function aggregate
carries `analysis_coverage`. It is required, not optional — a caller never has to
ask whether the numbers it just read were final.

```json
{
  "complete": true,
  "state": "complete",
  "analysis_running": false,
  "engine_state": "IdleState",
  "note": "Analysis had settled when this was read; the counts and lists are Binary Ninja's final answer for this view."
}
```

`complete` is the one-line check. `state` adds `unknown`, because "could not ask
the engine" is not the same as "finished" and must never be rounded to it.
`engine_state` is Binary Ninja's own `BNAnalysisState` and is for humans reading
logs — IDA fills the same field with `AU_*` constants, and the two vocabularies
have nothing to do with each other.

Under normal operation this reports `complete`, because the worker settles
analysis before answering. It earns its place in the cases where that is not
true: analysis aborted, or a view being held. Coverage is sampled *before* the
data is read, so a `complete: true` was still true when the data was taken.

`il.pseudo_c` deliberately does not carry it: one function is not an aggregate,
and the convergence wait already removes the failure mode the field would
describe.

**It describes one view, not two.** `update_analysis_and_wait` makes one view's
answer final. It does not make two independent loads of the same file agree, and
they demonstrably do not: reopening a saved `.bndb` continues analysis on what
is stored rather than replaying it, so it can settle on *more* than a fresh load
of the raw file. `/bin/cat`'s `main` reports 17 callees loaded from the ELF and
18 loaded from a database built from that same ELF, reproducibly, with both sides
reporting `complete: true`. The database is a fixed point; the raw file is not.

---

## Testing

```bash
cargo test --bins            # 54 unit tests; no Binary Ninja needed
cargo test --test two_paths  # 15 end-to-end tests; needs Binary Ninja + a license
```

The end-to-end tests **skip with a printed reason** when no license is found,
rather than failing, so plain `cargo test` is green on a machine without Binary
Ninja. A red suite that only means "not installed here" trains people to ignore
it.

The two byte-comparison tests load a `.bndb` built once per run, for the reason in
the section above: two independent analyses of the same raw file are not
guaranteed to agree, and a byte comparison across processes should assert that
one analysis renders identically through two paths — not that two analyses reach
the same conclusion, which is not true and should not be tested.

The suite also runs **one at a time**, behind a mutex. That is a resource
decision, not a correctness one: fifteen tests each starting a headless Binary
Ninja is more than one machine takes.

Gates: `cargo fmt --check` and
`cargo clippy --all-targets --no-deps -- -D warnings` are both clean.

---

## Known limits

* **Idle TTL.** Unused workers are closed after 1800 seconds (override with
  `BN_IDLE_TTL_SECS`; `0` disables reaping). A view with an inflight call is not
  idle. `session.close` and supervisor exit still kill workers immediately.
* **Annotations and patches are in-memory unless you save.** See
  [Where changes go](#where-changes-go).
* **Undo is last-in-first-out and cannot target an older patch.** `patch.revert`
  refuses rather than undoing the wrong thing. Take a `.bndb` checkpoint before a
  patching run if you need to get back to a specific point.
* **`session.list` cannot see other processes.** Each `serve` owns its own table;
  a cross-process registry would need a daemon, and there is none.
* **A Python script can end the session.** `print()` is safe; writing to file
  descriptor 1 directly is not. See [Python](#python) above.
* **`script.python` is not cancellable mid-core-call.** The timeout raises
  `KeyboardInterrupt`, which Python delivers between bytecodes — a call blocked
  inside Binary Ninja's core does not notice it until that call returns.
* **A spilled output file dies with its worker.** The `file://` URL from an
  oversized answer is valid until the view closes.
* **`analysis_coverage` describes one view, not two.** See
  [Analysis completeness](#analysis-completeness).

## Not done

* **There is no license-free CI.** Structural smoke tests that never touch
  Binary Ninja would need a fake backend, and that design is not written. Tests
  against the real core still need Commercial or Ultimate.
* **Whether a CI runner counts as licensed use is unresolved**, and it is a legal
  question rather than a technical one. Seats being unlimited is confirmed; that
  is not the same question.
* **No skills are shipped.** The `vibrev-skills` channel is deliberately not
  wired: this repository has no skill content, and a channel that can only answer
  "none" is not worth the three lines it costs. Wiring it comes after there is
  something to ship — a skill mapping Binary Ninja's API onto this tool surface
  is the obvious candidate.

## License

Apache-2.0.
