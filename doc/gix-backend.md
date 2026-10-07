# GixPython backend

Install the `gix` extra to make GitPython use GixPython for supported operations:
`GitPython[gix]`, or `.[gix]` from this checkout. GixPython is the distribution
name; `gix` is its import name. The extra uses the official PyPI release
`GixPython==0.1.0` on CPython 3.11 or newer. On older Python versions, the
dependency is omitted and GitPython uses the CLI backend. The ordinary
GitPython installation still supports Python 3.8 or newer.

To install from this checkout with an existing interpreter:

```sh
uv venv --python .venv/bin/python .tox/gix
uv pip install --python .tox/gix/bin/python --editable '.[test,gix]'
```

`tox -e gix` also resolves the published release from the package index.

GixPython 0.1.0 publishes macOS wheels. On Windows and Linux, installation
builds the released source distribution and requires Rust 1.89 or newer and
a platform C/C++ toolchain. Windows CI uses the runner's MSVC tools and a
stable Rust toolchain, with pip's built-wheel cache enabled.

Python extras add dependencies; they do not leave a runtime feature bit.
GitPython selects this backend when `gix` can be imported. Installing GixPython
separately therefore has the same effect. Use separate virtual environments to
compare the CLI and native installations. There is no backend environment
variable, constructor option, or runtime switch.

Git 2.52 or newer remains required. Unsupported operations and call options use
the existing CLI implementation. Public `repo.git.<command>()` calls retain
their command-line behavior. Native dispatch applies to library-managed calls.

Here and in coverage reports, **native means Gitoxide execution through
GixPython's `gix` API**. It never means Python-implemented Git behavior. Python
glue validates inputs, adapts Gix results and manages repository handles. For
example, object reads call `Repository.find_object()` and reference edits call
`Repository.edit_references_as()`. The two fixed metadata paths use
`Repository.git_dir()` plus the requested basename; that adaptation does not
provide general Git-path resolution. A `native` counter must represent a
Gix-backed operation, and backend timings include its Python glue and any CLI
fallbacks.

## Install and test without package indexes

The prepared environments in this checkout are `.venv` (CLI) and `.tox/gix`
(GixPython). Run either installation against a disposable repository fixture:

```sh
.venv/bin/python test/run-local.py --no-cov -q
.tox/gix/bin/python test/run-local.py --no-cov -q \
    --backend-report=.cache/gix-coverage.json
```

The runner uses local version tags, creates an isolated Git configuration,
prepares the historical test fixture inside a temporary shared clone, and
disables package-index access. Tests use local repositories, including the
tutorial example. The suite needs loopback sockets for its Git daemon and
permission to inspect its own child processes. It does not need a remote Git
server. Missing local tags or packages are errors, not invitations to download.

The ignored `.cache/gix-wheels` directory contains the published GixPython wheel and
the build/test dependencies available on this machine. To recreate an
environment with an already-installed CPython interpreter:

```sh
uv --cache-dir .cache/uv venv --offline --python .venv/bin/python .tox/gix
uv --cache-dir .cache/uv pip install --offline --no-index \
    --find-links .cache/gix-wheels --python .tox/gix/bin/python \
    --editable '.[test,gix]'
```

For another machine, populate that directory from PyPI or its package cache
before running the offline installation tests. Select wheels compatible with
the interpreter and platform; ordinary and free-threaded CPython use different
wheels. On platforms without a published wheel, first build one from the
released source distribution and retain it in the wheelhouse.

## Conversion coverage

The pytest header names the selected backend. Native runs print operation
counts and fallback reasons, and `--backend-report=PATH` saves the same records
as JSON. A record looks like:

```json
{"method": "IndexFile.write", "outcome": "CLI: split index preservation (GIX-13)", "count": 2}
```

Search the report for `not converted` to find remaining command adapters, and
for `GIX-` to find upstream limitations. A high-level method can use several
native and CLI operations; counts describe operations, not entire user calls.
The `git.backend` DEBUG logger reports these decisions outside pytest.
`git._backend.statistics()` returns a snapshot of the process-local counters.
Zero observed calls means untested in that run, not unsupported.

Successful `Git.execute` launches also appear as `CLI process` records. This
includes raw `repo.git` calls and failed Git commands that started a process,
but excludes failed process creation, direct subprocesses in test helpers,
other Python processes and Git's own child processes. A persistent `cat-file`
launch counts once; subsequent requests through it do not. These counts apply
to both installations and are separate from native/fallback decisions.

Pytest prints session launch totals split into setup, call, teardown and
collection/session work. `--backend-report` keeps its existing record-list
format and adds `pytest.*` phase records. The `Git.execute` record is
process-lifetime cumulative (including import-time probes); `pytest.session_total`
is the current session's total. Optional ceilings fail the test session on an
increase while allowing reductions:

```sh
.tox/gix/bin/python test/run-local.py --no-cov -q \
    --backend-report=.cache/gix-processes.json \
    --max-cli-processes=TOTAL --max-cli-test-processes=CALLS
```

Replace `TOTAL`/`CALLS` with baselines for the same selected tests and platform.
Setup is deliberately counted separately because fixture improvements and
test additions can change it independently of native backend capability.
These are pytest phases: `unittest.TestCase.setUp()`/`tearDown()` run inside
the call phase, so that column can still include their fixture work. Counts
cover the current Python process; they are not aggregated across xdist workers.
For a stable CI assertion, the pinned repository benchmark uses per-measurement
ceilings in `test/performance/cli-budget.json`: the warm Gix journey launches
one CLI process, opening launches one, and nested discovery launches three.
Reduce these ceilings as conversions land. The other operation rows have zero
ceilings except the one-process patch diff.

Before the Gix-only audit, this instrumentation on CPython 3.12.14/macOS arm64 and official
GixPython 0.1.0 recorded a full suite without coverage passing 1,674 tests and 38
subtests (79 skipped, one xfailed) in 408.81 seconds. It recorded **30,898
`Git.execute` launches**: 6,523 in pytest setup and 24,375 in call phases,
with zero in teardown or collection/session phases. The process-lifetime
counter is 30,899 because the import-time Git probe precedes pytest session
accounting. The same run recorded 21,409 fallback decisions. These totals
include explicit CLI tests and fixture commands, including non-Git commands
passed directly to `Git.execute`; they are a local baseline, not a count of
only fallback calls. The expanded warm benchmark instead isolates a user journey:
43 CLI launches versus one Gix launch, opening nine versus one, and nested
discovery eleven versus three after restoring the reference-format fallback
and sharing successful version checks.
The historical full-suite counts above predate this correction. A constant
`files` answer was not a Gix query; `GIX-1` records the remaining native
repository-format validation gap.

| GitPython entry point / managed command | Gix implementation | Remaining CLI cases |
| --- | --- | --- |
| `Git.get_object_header`, ODB `info` | Object resolution and native header lookup | Custom storage, unsupported revision grammar |
| `Git.stream_object_data`, ODB `stream` | Object bytes in an independent stream | Objects larger than 8 MiB; GIX-2 |
| Commit/tree serialization readback | Existing ODB stream; no separate `cat-file` process | The same storage and large-object fallbacks as ODB reads |
| `Repo` opening/discovery | Native storage, worktree, object format and empty-tree metadata | Repository-format validation, unsupported layouts/environment and native validation gaps; GIX-1/14/19 |
| Standalone discovery helpers | Native storage directories and gitfiles reopened at their canonical native Git directory | Rejected candidates and the same layout/environment guards as `Repo` opening; GIX-14 |
| `Repo.rev_parse`, `rev_parse` metadata queries | Revision lookup, common directory, object format, bare flag, worktree root, fixed `modules`/`COMMIT_EDITMSG` locations | Repository-format validation, other metadata paths, symlinked metadata leaves, message searches and describe forms; GIX-1/14/17/22 |
| Revision path/mode metadata | Native revision specification, including tree paths and index stages | Custom/sparse indexes, unsupported revision grammar or path normalization |
| Tree enumeration, `ls_tree` | Native tree entries with modes, names, and object IDs | Other command options |
| Reference object reads | One exact native lookup for direct, symbolic and absent references | Partial names and native decoding errors |
| Reference-name validation | Native full-name validation without opening a repository | Standalone names outside the native grammar; GIX-20 |
| Managed `symbolic_ref` | Nonrecursive target lookup | Mutation, command-level missing-reference diagnostics |
| Reference enumeration, `for_each_ref` | Sorted reference names and literal prefixes, preserving symbolic aliases | Dangling symbolic refs, root refs, glob patterns, other formats/options; GIX-25 |
| Managed `config --get KEY` | Merged repository config snapshot | Files/streams, enumeration, mutation; GIX-12 |
| Submodule enumeration and cached fields | Dedicated native `.gitmodules` parser over the existing worktree/blob source, with raw path/URL/branch values | Other/duplicate sections, ambiguous brackets, missing/implicit fields and parser errors; GIX-12 |
| Commit hooks | No bound native lookup/execution API | All hooks, including absent hooks; GIX-23 |
| Worktree inventory, `worktree list` | Main and linked worktree metadata, including bare main repositories and locks | Prunable entries; GIX-14 |
| `Repo.merge_base`, `Repo.is_ancestor` | Native graph queries for two revisions | Octopus/fork-point and other options |
| `Commit.count` | Reachable commit count, skip/limit/first-parent | Path filters and other revision options |
| `Commit.iter_items`, `Repo.iter_commits` | First-parent walks and a single tip | General history ordering; GIX-8 |
| Index entry reads, `ls_files` | Stage/mode/OID/path and exposed index flags | Custom and sparse indexes; GIX-3/4 |
| `IndexFile.version`, `update_index` query | Native index version | Actual `update-index` mutations |
| `IndexFile.write` and index persistence | Edit a private native index, publish through the existing lock | Custom, sparse, split, non-v2, unmerged, overlapping, or null-ID entries; GIX-3/4/13 |
| ODB `store`, managed `hash_object` | Native object hashing/writing with byte-fidelity preflight | Large/nonseekable input and changed serialization; GIX-2/5 |
| `IndexFile.write_tree` | Native tree editor with child-kind and null-ID validation | Missing non-gitlink children, invalid entries; GIX-7/24 |
| Tree serialization, `mktree` | Native tree editor with child-kind and null-ID validation | Missing children, unsupported or invalid entries; GIX-7/24 |
| Fresh index preparation, `read_tree` | Empty index or index from one tree | Existing index, merges, non-v2 selection; GIX-13 |
| `Commit.create_from_tree`, `commit_tree` | Explicit author/committer and unsigned UTF-8 commit | Identity cleanup, object-kind validation, other encodings, signature formats, signing/options; GIX-6/21/24 |
| Reference log reads, `reflog` | Existence and GitPython's reflog format | Orphan logs, arbitrary formats, writes; GIX-10 |
| Committer identity, `var` | Native process/config identity from `Repository.committer()` | Per-command identity overrides, other variables and normalization/identity errors; GIX-21 |
| Selected `set_object` / reference deletion, `update_ref` | Native ref edits with GitPython's existing validation | Strict create/CAS, branch-target validation, symbolic aliases other than HEAD, symbolic detachment, active-branch HEAD log, unchanged targets and log-message cleanup; GIX-9/10/21/24 |
| Tree/commit `Diffable.diff` | Raw change records and unambiguous exact renames | Patches, paths, index/worktree/root diff, inexact/ambiguous renames; GIX-11 |
| `Commit.stats` | Native Myers line counts, binary counts, first-parent tree comparison | Diff attributes, other algorithms, gitlinks, quoted filenames, large blobs; GIX-2/18 |
| `Repo.is_dirty` | Index/tree/worktree status, configured submodule checks and pathspecs | Custom/sparse indexes and non-root command directories |
| `Repo.untracked_files` | Native directory walk | Extra status options and non-root command directories |
| `Repo.ignored` | Native excludes with tracked-file suppression | Symlink/submodule traversal and unsupported path normalization |

Repository-backed native operations fall back for reftable (GIX-1) and repositories
with `extensions.compatObjectFormat` (GIX-19). Process-returning calls, timeouts,
custom storage/environment, global Git options, and unhandled command options
also retain their CLI contracts. A broken installed extension is reported as
an import error; only an absent top-level `gix` selects CLI mode.

## Performance work

Use the [measurements after the Gix-only audit](#measurements-after-the-gix-only-audit)
for the corrected implementation. Older snapshots retain their original
workloads and include shortcuts that were subsequently removed.

### Shared minimum-version checks

Both installations reuse successful minimum-Git-version checks across fresh
`Git` wrappers with the same resolved executable, executable metadata, working
directory, effective environment and `Git.refresh()` generation. Two extra
checks in the fixed warm probe now launch zero processes instead of two;
two equivalent cold wrappers launch one probe. Public `version_info` caching
remains per instance, and old versions still fail before repository creation.

This is shared CLI housekeeping: it caches an actual Git answer and records
no native success. It is not a Gix implementation of a missing capability.
The pinned warm Gix opening/discovery ceilings fall from 2/4 to 1/3 here;
the reference-format query and rejected-candidate diagnostics remain real CLI
calls. Cold contexts can still require a version probe.

Global Git options and ambiguous Windows executable search retain per-instance
probes; explicit absolute executables can share checks on Windows. The shared
cache is bounded to 128 contexts. Call `Git.refresh()` if a launcher's reported
version changes through external state without changing its executable or
environment metadata.

### Existing-repository benchmark

[`test/performance/README.md`](../test/performance/README.md) describes the
`pyperf` harness and fixed GitPython 3.1.45 fixture. It measures eleven public-API
operations and their complete journey on one already-open `git.Repo`, plus
separate direct opening and discovery from `git/objects`. Fresh high-level
wrappers preserve the cost of actual operations; imports, fixture preparation
and parity preflight are outside timing. Native repository refresh remains
inside operation timing, so these measurements include the cost of keeping
retained state current.

Submodule inventory, revision path/mode lookup and raw commit/tree readback
extend the already-open journey, each with a zero-CLI ceiling. The readback
measurement reads existing bytes, including the signed fixture commit, without
rewriting objects. Historical tables below retain their original workloads.

At `244e418da6cc43de129cbe2908d11be4c5ad457a`, using official GixPython
0.1.0 and the same existing CPython 3.12.14/macOS arm64 interpreter for both
installations, with Git 2.54.0 (Apple Git-157), six worker processes with three values each produced the
following means and standard deviations. GixPython ran first, then CLI;
all eleven result digests matched. The fixture has one branch, one untracked
file and an ignored directory, with ambient Git configuration disabled.

| Measurement | CLI (ms) | GixPython (ms) | CLI / Gix |
| --- | ---: | ---: | ---: |
| Already-open journey | 230.90 ± 6.87 | 260.14 ± 13.37 | 0.89× |
| Reference inventory | 22.77 ± 1.15 | 1.17 ± 0.26 | 19.52× |
| 25 first-parent commits with metadata | 9.24 ± 0.46 | 73.61 ± 7.24 | 0.13× |
| Root tree and README blob | 16.02 ± 1.07 | 2.40 ± 0.46 | 6.66× |
| Index entries | 8.43 ± 0.57 | 2.00 ± 0.38 | 4.21× |
| Commit count and ancestry queries | 82.28 ± 2.27 | 36.19 ± 0.84 | 2.27× |
| Latest diff and commit statistics | 29.98 ± 1.66 | 60.98 ± 2.45 | 0.49× |
| Patch diff (includes CLI fallback) | 17.87 ± 1.28 | 10.86 ± 1.01 | 1.64× |
| Dirty/untracked/ignored paths | 68.56 ± 3.18 | 64.74 ± 2.00 | 1.06× |
| Direct opening and close | 95.08 ± 4.64 | 35.84 ± 2.02 | 2.65× |
| Nested discovery and close | 112.58 ± 5.38 | 49.20 ± 4.16 | 2.29× |

Ratios above one favor GixPython. This workload's complete journey is about
13% slower with GixPython: metadata reads and commit statistics offset gains
elsewhere. These are warm-cache measurements on one machine, with `pyperf`
stability warnings for several samples; they do not establish a general
speedup. Full-suite times below also include setup and coverage.

The separate `Backend benchmark` CI job runs both installations on one runner,
publishes every measurement and `pyperf` significance reporting, and retains
raw JSON and comparison artifacts. Results include revisions and per-operation
native/fallback decisions. Adding a `MEASUREMENTS` entry extends the journey,
individual timings and parity checks together. Opening/discovery remain
separate lifecycle measurements. CI fails on execution/parity errors; timing
ratios are observational on shared runners.

### Historical retained-handle and opening measurements

These results predate the Gix-only audit. The measured implementation inferred
reference format, repaired linked-worktree metadata and rejected some discovery
candidates in Python. Its zero-CLI counts and associated opening speedups do
not establish Gix coverage and are superseded by the corrected implementation.
Keep the raw observations below only as a historical record.

At `c49bbec0afb806df66a33fa9c5d76e21ac8f0314`, the same pinned fixture,
official GixPython 0.1.0 and existing CPython 3.12.14/macOS arm64 interpreter
were measured sequentially, Gix first and CLI second, after tests finished.
Each backend used three worker processes, three values per worker, four loops
per value and one warmup. All eleven result digests matched and the checked-in
CLI ceilings passed. Raw local results are
`/private/tmp/gitpython-retained-final-{gix,cli}.json`; this table is a journal
snapshot, while CI continues to publish fresh measurements.

| Measurement | CLI mean ± stdev (ms) | GixPython mean ± stdev (ms) | CLI / Gix | Native / fallback | CLI launches: CLI / Gix |
| --- | ---: | ---: | ---: | ---: | ---: |
| journey | 209.44 ± 17.65 | 263.25 ± 5.52 | 0.80× | 55 / 2 | 23 / 1 |
| inventory | 19.76 ± 0.78 | 0.89 ± 0.03 | 22.30× | 3 / 0 | 3 / 0 |
| history_25 | 7.49 ± 0.17 | 79.02 ± 9.67 | 0.09× | 26 / 0 | 1 / 0 |
| browse_tree_and_blob | 13.55 ± 0.39 | 2.06 ± 0.41 | 6.59× | 5 / 0 | 2 / 0 |
| read_index | 6.96 ± 0.08 | 2.59 ± 0.47 | 2.69× | 1 / 0 | 1 / 0 |
| revision_graph | 63.27 ± 2.57 | 32.72 ± 0.22 | 1.93× | 9 / 0 | 6 / 0 |
| diff_and_stats | 20.78 ± 0.37 | 65.33 ± 1.25 | 0.32× | 5 / 0 | 3 / 0 |
| patch_diff | 14.06 ± 0.39 | 8.61 ± 0.08 | 1.63× | 3 / 2 | 2 / 1 |
| worktree_status | 56.61 ± 1.43 | 70.68 ± 2.18 | 0.80× | 3 / 0 | 5 / 0 |
| open_repository | 69.28 ± 0.59 | 1.00 ± 0.07 | 69.20× | 1 / 0 | 11 / 0 |
| discover_repository | 81.68 ± 0.68 | 0.90 ± 0.19 | 90.52× | 1 / 0 | 13 / 0 |

The pre-audit implementation launched no CLI processes for these opening and
discovery probes. It measured about 69× and 91× faster lifecycle operations,
while the complete already-open journey was about 26% slower with Gix. These
lifecycle ratios include the shortcuts removed by the audit. Retaining a Python
handle alone does not resolve the existing history/statistics costs. Several
rows have `pyperf` sample-size or variability warnings, so timings describe
this machine and workload rather than a general speed guarantee.

The full Gix suite without coverage passed **1,678 tests and 38 subtests**,
with 79 skips and one expected failure, in **337.51 seconds (5m 37.51s)**.
One expected path-expansion deprecation warning was reported. It recorded
**22,319 `Git.execute` launches**: 3,833 setup, 18,486 call, zero teardown or
collection/session. The process-lifetime count is 22,320 including the import
probe. Against the preceding 408.81-second/30,898-launch baseline, this local
run took 17.4% less time and launched 27.8% fewer CLI processes; the suite has
four additional regressions, and the timing comparison is observational.

Affected tests ran with Gix before CLI: 304/264 repository, command, backend
and safety tests; 136 command-guard tests per backend; 31 positional tests per
backend; 13 process-count/budget tests per backend. Repository suites also
passed 14 subtests, with three skips. Ruff lint/format, mypy and basedpyright
passed. Both code changes are separate Tix commits: `02e2cc44` retains native
handles and the original `c49bbec0` attempted zero-launch opening/discovery.
The rewritten opening commit restores real format queries and native metadata
fallbacks; the current coverage table and ceilings reflect those requirements.

### Measurements after the Gix-only audit

At `5ef5c62f2e2dafe3e7ddb0deed6998fd7092d360`, the adapters used Gix for
supported operations and retained CLI fallback for missing native capabilities.
The audit removed Python reference-format inference, metadata-path construction,
committer resolution, reflog cleanup, discovery repairs and absent-hook success.
Its findings were recorded in GIX-1/10/14/21/22/23; the capability follow-up below
refines those requirements. Retained native repository state and conversions
that actually use Gix APIs remain in place.
The full-suite and timed benchmark figures in this section describe that
snapshot, before the subsequent metadata and discovery changes.

The full Gix suite without coverage passed **1,710 tests and 38 subtests**,
with 79 skips, one expected failure and one existing path-deprecation warning.
It took **342.36 pytest seconds / 342.80 seconds including the runner
(5m 42.80s)** on existing CPython 3.12.14/macOS arm64, official GixPython 0.1.0
and Git 2.54.0. This includes CLI-inventory and Trace2 overhead.

The corrected run recorded **22,694 `Git.execute` launches**. The earlier
12,394-launch result included the removed Python shortcuts and is superseded
as a coverage claim. The corrected run also contains 19 additional regression
cases; these are observed totals for their respective revisions.

| Launch source | Before audit (`d2e788a1`) | Corrected (`5ef5c62f`) |
| --- | ---: | ---: |
| Managed operations with Gix enabled | 8,836 | 16,871 |
| Managed operations with Gix explicitly disabled | 309 | 339 |
| Minimum-version probes | 2,483 | 4,698 |
| Raw `Git.execute` calls | 766 | 786 |
| **Total pytest launches** | **12,394** | **22,694** |

The corrected total splits into 4,464 setup and 18,230 call-phase launches,
with zero in teardown or collection/session. Call phases include `unittest`
fixture work. The Python inventory reconciles exactly with the pytest counter;
the process-lifetime backend count is 22,695 including its import probe.
Trace2 additionally identifies 3,685 Git child processes and 37 processes
outside the captured wrapper. Its total overlaps the Python inventory, so the
two totals must not be added together.

The benchmark used the same pinned GitPython 3.1.45 repository and interpreter
for both backends, sequentially after tests, Gix first and CLI second. Each
used three worker processes, three values per worker, four loops per value
and one warmup. All **14 result digests matched**, and every corrected CLI
ceiling passed. The eleven operations form one journey on an already-open
`Repo`; opening and discovery remain separate lifecycle measurements.

| Measurement | CLI mean ± stdev (ms) | GixPython mean ± stdev (ms) | CLI / Gix | Native / fallback | CLI launches: CLI / Gix |
| --- | ---: | ---: | ---: | ---: | ---: |
| journey | 314.35 ± 2.33 | 264.94 ± 3.30 | 1.19× | 79 / 2 | 43 / 1 |
| inventory | 19.50 ± 0.31 | 0.99 ± 0.08 | 19.68× | 3 / 0 | 3 / 0 |
| history_25 | 7.59 ± 0.12 | 73.32 ± 2.17 | 0.10× | 26 / 0 | 1 / 0 |
| browse_tree_and_blob | 13.45 ± 0.21 | 1.78 ± 0.22 | 7.55× | 5 / 0 | 2 / 0 |
| read_index | 7.00 ± 0.11 | 2.09 ± 0.27 | 3.35× | 1 / 0 | 1 / 0 |
| submodule_inventory | 72.10 ± 0.71 | 3.21 ± 0.20 | 22.44× | 13 / 0 | 11 / 0 |
| revision_paths | 55.27 ± 0.42 | 1.41 ± 0.12 | 39.12× | 6 / 0 | 8 / 0 |
| object_readback | 6.60 ± 0.16 | 1.22 ± 0.10 | 5.43× | 5 / 0 | 1 / 0 |
| revision_graph | 62.26 ± 1.15 | 33.25 ± 0.36 | 1.87× | 9 / 0 | 6 / 0 |
| diff_and_stats | 21.43 ± 1.28 | 67.83 ± 7.58 | 0.32× | 5 / 0 | 3 / 0 |
| patch_diff | 13.96 ± 0.12 | 8.97 ± 0.23 | 1.56× | 3 / 2 | 2 / 1 |
| worktree_status | 36.59 ± 1.01 | 70.55 ± 4.64 | 0.52× | 3 / 0 | 5 / 0 |
| open_repository | 58.47 ± 1.12 | 7.71 ± 0.25 | 7.58× | 1 / 1 | 9 / 1 |
| discover_repository | 70.72 ± 0.68 | 20.49 ± 0.38 | 3.45× | 1 / 5 | 11 / 3 |

The expanded warm journey is **1.19× faster** with Gix in this sample, with
43 CLI launches reduced to the single patch-diff launch. Opening is **7.58×
faster** and retains one reference-format query; discovery is **3.45× faster**
and adds two CLI queries for rejected native candidates. Its five fallback
decisions include both discovery and command-adapter decisions, while only
three processes are launched. Cold contexts can also need a version probe.
The previous zero-launch opening/discovery results included Python substitutes
and are historical only.

History, diff/statistics and worktree-status measurements remain slower with
Gix despite making no CLI launches. They need separate profiling. Several
rows have `pyperf` sample-size or variability warnings; these measurements
describe this machine and workload rather than a general speed guarantee.

Every affected selection passed with Gix before CLI. The final full suite above
used Gix; CLI validation used the affected selections. Repository-wide Ruff
lint/format, mypy and basedpyright passed. The benchmark comparison independently
checked result parity, fixture/source identity and all process ceilings.
Generic configuration and standalone reference-name gaps remain documented
under GIX-12/20. `Repo._get_gix_repository(recreate=True)` still explicitly
recreates retained native state; its snapshot limitations are documented below.

Raw benchmarks, comparison tables and logs from that snapshot are under
`.cache/gix-only-audit/benchmark-*` and `.cache/gix-only-audit/pyperf-comparison.md`.
The joined inventory, per-call CSV/JSONL, grouped commands, passing full-suite
log and runner timing are in `.cache/gix-only-audit/full-inventory-5ef5c62/`.
The older `.cache/gix-conversions/benchmark-{gix,cli}.json` and
`final-inventory-d2e788a/` remain historical evidence. CI continues to publish
fresh measurements and enforce the checked-in operation-specific ceilings.

### Native capability follow-up

The follow-up used the same official GixPython 0.1.0 and existing CPython
3.12.14, with runtime and test code at
`ee947c98540396d5644f3a7fea7c807633f4b5b8`. Each implementation change was
amended into its corresponding Tix commit and checked with Gix before CLI.

- Reference storage can already be identified through native config. Direct
  SHA-1 and SHA-256 regressions confirm that reftable `HEAD` access raises
  `gix.Error` with an unsupported-storage cause; the binding does not expose a
  separate `Unsupported` exception. Strict native opening and `HEAD` access
  still accept unknown repository extensions that Git rejects, so the CLI
  format query remains necessary for validation (GIX-1).
- Native `git_dir()` supplies the locations for `modules` and `COMMIT_EDITMSG`,
  including linked worktrees. The adapter now adds only those fixed leaf names,
  after reopening noncanonical Git paths through Gix. Each ordinary lookup
  drops from one CLI launch to zero. Other metadata names and symlinked leaves
  retain Git's path resolution (GIX-22).
- Gix already exposes the worktree of a bare main repository. Combining its
  configured `is_bare()` flag with `workdir()` fixes opening and inventory
  in the adapter; the original classification difference remains tracked as
  an upstream compatibility bug. Gitfiles are reopened at their
  canonical native Git directory with the same strict options; supported
  symlinked-target helpers now need zero CLI launches instead of one. This
  also prevents an arbitrary gitfile location from becoming the worktree.
  Dangling `commondir` handling and typed failure information remain gaps;
  rejected candidates keep Git diagnostics (GIX-14).
- Native snapshot overrides resolve committer name, email and date. A cheap
  independent repository clone is needed to isolate per-command overrides:
  Python copying is unsupported and the internal binding clone shares state.
  Shared snapshots and process environment remain untouched (GIX-21).
- `LogChange` already configures each ref edit's message and log policy. A
  direct native regression preserves whitespace where Git normalizes it, so
  message cleanup still needs a native helper or policy (GIX-10).

Final focused validation passed **120 Gix tests and 14 subtests** (one skip)
in 22.93 seconds, followed by **34 CLI tests and 14 subtests** (two skips,
including the native-only module) in 6.14 seconds. This covered the complete
native-backend, launch-counter and benchmark-comparison modules plus the
affected shared discovery, gitfile, worktree and repository-construction tests.
Repository-wide Ruff lint/format, mypy and basedpyright passed.

An untimed benchmark preflight, Gix first and CLI second, matched all **14
result digests** and passed the existing launch ceilings. The warm journey
remains CLI/Gix **43/1** launches, opening **9/1**, and nested discovery
**11/3**; the new fixed-path and gitfile-helper reductions are asserted by
their focused tests. No full-suite rerun or fresh timed benchmark is claimed
for this follow-up. Logs, backend reports and the count comparison are under
`.cache/gix-capability-followup/` (`15-final-*` and `16-benchmark-*`).

### Windows CI process overhead

The Python 3.12 jobs in [PR #2274's Python package run](https://github.com/gitpython-developers/GitPython/actions/runs/37628358853)
spent 57m 25s in pytest on Windows and 5m 2s on Ubuntu. Their process reports
counted 85,777 and 82,683 `Git.execute` launches respectively. The Windows
submodule test modules accounted for approximately 36 minutes, based on the
timestamps of their test results; the delay was spread across many operations.

A local Windows profile of `test_file_handle_leaks` and
`test_update_no_fetch_is_recursive[root-no-fetch]`, with CI's coverage and
pytest options, counted 2,447 launches. About 65 of 77 seconds were spent in
Git command execution, including 44 seconds in repository construction;
forced garbage collection accounted for about three seconds. Combining
`--show-ref-format`, `--show-object-format`, `--is-bare-repository` and
`--git-common-dir` in one `rev-parse` invocation reduced the same selection to
2,009 launches: three saved for each of 146 repository opens. Git still
computes all four values. The common-directory path is last and split only
after the three scalar fields, preserving paths containing newlines.

Three paired measurements of 20 ordinary repository opens on Windows gave
median times of 300.74 ms before and 221.18 ms after, with matching metadata
and 11 versus eight launches per open. These use CPython 3.12.13 and Git
2.55.0.windows.3; timing is observational, while the launch reduction is
checked by the regression tests.

A 50-call `git version` probe on the same host measured median times of
17.49 ms per call on Windows and 1.27 ms in Ubuntu WSL, which uses CPython
3.14.4 and Git 2.53.0. Even trivial Git commands carry appreciable startup
cost on Windows.

This optimizes the CLI backend's construction path. Supported Gix discovery
still uses its native metadata and the separate Git format-validation query;
the Gix launch ceilings and open compatibility bugs remain unchanged.
CI now includes `--durations=30` so subsequent slow tests are visible directly.
Local Windows reproduction must retain CI's `core.autocrlf=true` setting and
place pytest's temporary directories outside a Git checkout. Isolating all
Git configuration without restoring that setting changes the newline test;
placing `--basetemp` under this checkout lets empty-directory Git probes
discover the parent repository instead.

The full local baseline at `105114db` recorded 86,032 launches in 3,990.28s;
the two submodule modules accounted for 2,421.59s. It had 1,652 passing tests
and the two harness failures described above, both of which passed unchanged
after correcting the setup. The patched run exited successfully with 1,662
passed, 60 skipped, nine expected failures, two unexpected passes and 40
passing subtests. It recorded 77,732 launches in 3,715.16s. These runs
overlapped, so their wall times are not a controlled comparison. The paired
repository-open benchmark above measures the affected operation separately.
Logs, profiles, JUnit results and backend reports are retained locally under
`.cache/ci-performance/`.

### Test-suite setup measurements

The fixture optimizations below are implemented as separate commits, each
validated with GixPython before CLI.
The original local measurements use official GixPython 0.1.0 and existing
CPython 3.12.14 on macOS arm64 at `89c609cf92335e75652d7725682e215a9ea080e5`.

The full suite with coverage took 757.85 seconds wall-clock (757.04 seconds
reported by pytest): 1,649 tests and 38 subtests passed, 79 skipped, and one
expected failure. Operation reporting counted 114,800 native operations and
39,002 CLI fallback decisions. Those decisions are not a complete subprocess
count: raw `repo.git` calls and subprocesses started by Git are not all counted.

### Retain native repository state (implemented)

Each `git.Repo` owns a native `gix.Repository`. Managed operations access it through
`Repo._get_gix_repository()`, which reuses the instance by default.
`Repo._get_gix_repository(recreate=True)` replaces it explicitly; this method is
the control point for a future configurable reuse policy. Managed operations reuse it;
`close()` releases it, and a later operation can reopen it. Pickling excludes
native resources and restores the command's weak owner reference. Gix provides
thread-safe handle access and automatic index/ODB snapshot refresh. A per-Repo
lock serializes handle refresh, without serializing read operations.

Retaining native state is an intentional deviation from Git's fresh process per
command. Configuration/environment and observed CLI changes trigger best-effort
refresh, but this is not a promise that every external filesystem change is
immediately visible in every native cache. Explicit recreation or closing and
reopening the `Repo` provides fresh native state. Configuration queries currently
use a separate fresh handle because the retained execution handle overrides
hooks, fsmonitor and automatic maintenance; those overrides must not leak into
configuration results. The accessor itself removes no CLI calls: ten supported
metadata queries launch zero processes before and after this refactor.

Configuration and storage metadata changes, environment changes and raw CLI
launches cause `reload()` before reuse. Configuration queries use a separate
fresh handle so synthetic safety settings never appear as user settings.
Configurations with includes conservatively reload on each operation because
the binding does not expose all included source paths. Storage overrides,
reftable and compatibility object formats retain their existing CLI guards.

An earlier 1,000-call benchmark without coverage measured an object read using
one native handle at 0.046 ms per call, compared with 0.635 ms through the
fresh-open stream adapter. Opening and validating a native repository alone
took 0.418 ms per call. These small repeated-read measurements do not estimate
whole-suite speedup.

### Reuse prepared test fixtures (implemented)

A 19-case submodule rejection sample without coverage took 15.62 seconds:
1,258 `Git.execute()` calls accounted for 11.86 seconds, while 1,995 native
repository-open/validation attempts accounted for 0.84 seconds. Most work was
fixture setup. This sample supports prioritizing repeated setup subprocesses;
it is not a profile of the entire suite.

The original collection found 1,729 parameterized cases from 703 distinct source bodies.
Source inspection identified the following conservative set of 422 cases whose
assertions do not require changing repository state after preparation. The
remaining cases have not been exhaustively classified; these are reuse
candidates, not proof that a shared fixture is safe in every execution order.

| Original cases | Repeated setup | Implemented change |
| --- | --- | --- |
| 166 | `TExc` (157) and `TestActor` (9) inherit repository-building `TestBase`. | Use the existing `TestCase` base without repository setup. |
| 182 | Three submodule rejection bodies repeatedly build `movable_submodule`, then check snapshots for no mutation. | Prepare logical-name baselines once and copy the parent per case, retaining fresh wrappers and independent writable files. |
| 51 | Six submodule rejection bodies prepare nested metadata, separate metadata, intermediate/leaf symlinks, or retained metadata before checking rejection. | Cache ten prepared layouts and restore complete copies at their original paths, preserving absolute Git links and symlinks. Cleanup removes the active copy even after failure. |
| 15 | Eight revision-query bodies rebuild the same four-commit graph, refs, index, and reflogs through `rev_parse_repo`. | Prepare the graph once and copy it for every consumer, including mutating cases; recreate repository, branch and commit wrappers. |
| 8 | Tree lookup bodies clone and check out `0.3.2.1` through `with_rw_repo`. | Read the historical tree directly through the existing class repository, removing clones and checkouts. |

The `movable_submodule` baseline also serves mutating cases: all writable
refs, index, config, objects, worktree and module metadata are filesystem copies,
while the local clone source remains shared and immutable. The original 322
consumers no longer repeat repository initialization and submodule cloning.
The original 68 `local_submodule` cases copy both source and parent from one
prepared two-commit layout because these tests also mutate the source. The
fixture relocates all source URLs and records the private URL in parent history
for `RootModule` comparisons. No mutable Git metadata is hard-linked.

Historical dependency sources are now lazy session fixtures. Originally all
25 `TestBase` classes reconstructed both sources (50 builds), although only four
classes called the URL helpers. The suite now prepares each needed source once,
with consuming tests retaining independent writable clones.

Four additional checks exercise isolation: edits and refs in movable copies,
restoration after deliberate mutation with an absolute symlink, private source
commits, and revision-graph changes. Existing security no-side-effect snapshots
remain in place. Native repository lifetime and refresh limitations are
documented above.

Per-change affected tests on existing CPython 3.12.14/macOS arm64 with official
GixPython 0.1.0, without coverage (wall-clock seconds including runner setup):

| Change | Passed cases | GixPython first | CLI second |
| --- | --- | --- | --- |
| Repository-free actor/exception tests | 166 | 0.47 s | 0.49 s |
| Lazy historical sources, all consumers | 206, plus 14 subtests; 6 skipped, 1 xfailed | 90.89 s | 160.82 s |
| Movable baseline, top-level submodule tests | 333 | 88.63 s | 178.75 s |
| Prepared rejection variants | 51 | 12.34 s | 26.23 s |
| Layout restoration check | 1 | 1.33 s | 1.62 s |
| Prepared revision graph | 23 | 4.39 s | 7.57 s |
| Historical tree lookups, whole tree module | 22 | 1.66 s | 3.86 s |
| Prepared no-fetch source and parent | 69 | 56.27 s | 117.52 s |

These selections overlap, and their timings are validation records rather than
isolated before/after benchmarks. The full-suite measurements below provide the
broader comparison. Only the existing interpreter was used.

At `c8ee26c7da373e28cc7ede17ef2eaadd763fcdfc`, the full GixPython suite
with coverage passed in **404.61 seconds wall-clock (6m45s)**, with pytest
reporting 404.12 seconds: 1,653 passed, 79 skipped, one expected failure,
and 38 subtests passed. Coverage remains 90%. Compared with the original
757.85-second run, this saved 353.24 seconds (46.6%, about 1.87 times faster).
This is one local before/after run per revision, not a statistical benchmark.

The same operation counters now record 102,581 native operations and 21,402
CLI fallback decisions, down from 114,800 and 39,002 respectively. Raw Git
calls and child processes remain outside those counters.

The subsequent full CLI run with coverage passed in **755.78 seconds
wall-clock (12m36s)**, with pytest reporting 755.30 seconds: 1,617 passed,
80 skipped, one expected failure, and 38 subtests passed. CLI coverage is 82%;
backend-specific tests account for different collection and coverage. This CLI
run validates the optimized suite; there is no matching pre-change CLI full-run
measurement here. Repository-wide Ruff lint/format, mypy and pyright passed.

## GixPython / Gitoxide follow-up ledger

These are local findings, not filed issues. **Every observed divergence from
the equivalent Git operation is a compatibility bug**, including intentional
differences. Gix must offer matching behavior, at least through an API or mode
as strict as Git. This covers acceptance/rejection, validation, returned data,
ordering, paths and mutation side effects. `strict_config(True)` and
`bail_if_untrusted(True)` alone do not provide that guarantee (GIX-1/14).

The status distinguishes reproduced bugs from missing APIs and unverified
coverage. Low-level primitives can remain available, but a compatible API or
mode is still required. An adapter workaround, including reopening through
Gix, does not close an upstream compatibility bug. Retain its expected/actual
behavior, version and reproduction until the upstream fix or compatible mode
has been verified. Python must not implement the missing Git behavior.

Unless stated otherwise, the evidence uses official GixPython 0.1.0, its pinned
Gitoxide revision `f819565c2c4c56619c4888acef6cf3b8144cbccb`, and Git 2.54.0 on
macOS arm64 with existing CPython 3.12.14. The repository and commands below
identify the historical fixture where needed.

| ID | Status | Finding and evidence | Required Gix behavior/API |
| --- | --- | --- | --- |
| GIX-1 | Bug; missing API | Native config exposes `extensions.refStorage`; reading `HEAD` in SHA-1/SHA-256 reftable repositories raises `gix.Error` with an unsupported-storage cause. However, strict native opening plus a successful `HEAD` read accepts unknown version-1 extensions that Git rejects. It also accepts `extensions.refStorage=files` with repository version 0, which Git rejects. | Git-compatible repository-format/extension validation, typed native errors, and eventual reftable support. A dedicated format getter is not needed just to identify storage. Keep the CLI format query because it also validates the repository, with regressions for both the unsupported-HEAD signal and unknown extensions. |
| GIX-2 | Missing API | Object lookup buffers full contents. `write_blob_stream` also reads its input into memory. | Bounded-memory object readers/writers usable by Python. The adapter currently caps native blob transfers at 8 MiB. |
| GIX-3 | Missing API | Index bindings open the repository's index but cannot load an arbitrary existing index file. `set_path()` only chooses its write destination. | An index loader accepting a path, including relative-path semantics. |
| GIX-4 | Missing API | Sparse index expansion is not exposed. | Expansion preserving skip-worktree and other metadata before editing. |
| GIX-5 | Unverified | Structured-object writers may decode/re-encode supplied bytes. This is a compatibility guard, not a demonstrated corruption bug. | A raw-object writer, or a guaranteed byte-preserving contract. The current adapter checks the round trip in an in-memory ODB first. |
| GIX-6 | Missing API | Native commit construction accepts a string message. GitPython also supports arbitrary message bytes and other declared encodings. | Byte-message commit construction with explicit encoding/signature semantics. |
| GIX-7 | Missing API | Native tree editing requires existing non-gitlink child objects. Git's `mktree --missing` / `write-tree --missing-ok` permit missing children. | Missing-object tree construction with equivalent validation. |
| GIX-8 | Bug | General revision iteration differs from Git's default ordering. The same fixture enumerated 5,439 commits in both engines, with the first ordering difference at position 178. Its 1,923-commit first-parent chain matched. | A Git-compatible walk order; counts and first-parent walks already work. See the reproduction notes below. |
| GIX-9 | Bug | `PreviousValue.MustNotExist` accepts an existing ref already at the requested target. Native tests explicitly permit this; Git's strict create/CAS rejects it. | A strict native expectation, enforced under the same ref lock. A Python existence precheck would race. |
| GIX-10 | Bug; missing API | `LogChange` preserves `  keep\t  spaces  ` where Git stores `keep spaces`. Updating the checked-out branch directly or through an alias omits the HEAD log entry Git appends. Updating that branch to its unchanged target also omits Git's HEAD log entry. Detaching symbolic HEAD records a null old OID instead of Git's resolved previous commit. `RefLog.Only` cannot express an independent arbitrary old OID, and reference-bound readers cannot access orphan logs. | Fix message normalization, secondary HEAD logging and old-OID selection in Gix, at least in a Git-strict transaction mode; expose raw reflog append and orphan-log access. `LogChange` already configures each edit's message, mode and force-create flag; `core.logAllRefUpdates` controls creation, not cleanup. Keep the existing `_update_ref` and `_reflog` fallbacks before mutation; do not normalize messages in Python. |
| GIX-11 | Unverified | Inexact and ambiguous rename pairing/scores have not been established as Git-compatible. This is a conservative guard, not a claimed native bug. | Verified pairing, scoring, tie-breaking and option parity. Exact unambiguous renames are native. |
| GIX-12 | Missing API | Generic config bindings lack standalone parsing, ordered section/key enumeration, multivars, unset/remove-section and source-scoped queries. Dedicated `.gitmodules` parsing is available and now used for supported submodule reads. | Those operations for `GitConfigParser` and remote/branch configuration. Native merged getters cannot replace repository-only config readers. |
| GIX-13 | Bug; missing API | Native index writing normalizes v4 to v2, offers no version setter, and expands split indexes. | Version and split-index preservation. Tests now assert that a split index remains split after an update. |
| GIX-14 | Bug; missing API | For a linked worktree of a bare main repository, `is_bare()` returns true while `git rev-parse --is-bare-repository` returns false; `workdir()` does expose the worktree. Initial gitfile opening can retain a noncanonical target and use an arbitrary gitfile's location as the worktree, unlike Git. Discovery accepts undecodable HEADs until explicit `head()` decoding and ignores dangling `commondir` symlinks that Git rejects. Bindings flatten failure kinds into `gix.Error`. Windows also exposes adapter path-formatting differences and a worker panic on an undecodable `commondir`; see the Windows reproduction below. | Provide Git-compatible classification, canonical gitfile locations and layout validation, plus typed errors instead of panics. Format native locations compatibly with Git's command output. The adapter combines Gix metadata, reopens through Gix and forces HEAD decoding, retaining CLI for remaining validation/diagnostic gaps. Those workarounds do not close these compatibility bugs. A Git-strict mode must cover these cases; strict config and trust settings alone do not. |
| GIX-15 | Bug | Native blame disagrees with Git even with Myers and rewrite tracking selected. In the fixture's `README.md`, lines 150 and 158 are attributed to the opposite commits. Incremental order also differs. | Attribution and incremental-output parity before replacing `Repo.blame` / `blame_incremental`. |
| GIX-16 | Bug; missing API | Native archive streaming takes a tree rather than a commit. Its TAR omits Git's global PAX commit comment, leaves `export-subst` placeholders literal, and writes ordinary modes as `0644` where Git uses `0664`. | Commit-aware export substitution, metadata and permission parity. Both engines respected `export-ignore` in the probe. |
| GIX-17 | Bug | Revision parsing accepts abbreviated IDs with `-dirty`, prefers the OID suffix over an exact describe-shaped tag, and treats escaped braces in message searches differently. | Git-compatible revision grammar and regex semantics. Existing `test_rev_parse.py` cases reproduce all three. |
| GIX-18 | Bug; missing API | The tree-diff resource cache reads attributes from the index; Git also consults worktree attributes. Native binary classification with textconv configured can also differ even in `to_git` mode. | Independent attribute-source control and `--no-textconv` parity. Statistics currently fall back for any effective `diff` attribute. |
| GIX-19 | Unverified | GixPython opens repositories with `extensions.compatObjectFormat`, but translation and object-write compatibility have not been validated. The installed Git reports `compatibility hash algorithm support requires Rust` when asked to translate an ID. This is an unvalidated capability guard, not evidence of missing native object mappings. | Verify compatibility-format reads, writes and OID translation against a Git build that supports them. All operations use CLI in the meantime. |
| GIX-20 | Bug; missing API | `Target.Symbolic(name)` validates full names but rejects standalone names accepted by `git check-ref-format --allow-onelevel`. Four of 430 audited calls differed: `refs` twice, `hellothere`, and `valid_one_level_refname`. Further probes include digits, punctuation and Unicode (`1`, `A1`, `HEAD_1`, `A-B`, `A.B`, `Ä`). | Expose Git-compatible partial/one-level name validation, or correct the native restriction where appropriate. This is a binding/behavior shortcoming to revisit upstream; standalone names rejected natively retain CLI validation. |
| GIX-21 | Bug; missing API | `Repository.committer()` preserves a process identity of ` Name. ` / ` email@example.invalid ` while `git var GIT_COMMITTER_IDENT` returns `Name.` / `email@example.invalid`. Native snapshot overrides for name, email and date work, but modifying the retained snapshot would leak per-command identity across threads. GixPython 0.1.0 has no general independent repository clone: Python copying fails and internal `RepoHandle::clone()` shares its `Arc` state. | Expose Git-compatible identity cleanup and a cheap independent native clone with isolated config, including per-command removal semantics. Reopening isolates state but repeats setup; `with_object_memory()` changes object-write behavior and is not a general clone. Keep `_checked_signature` validation and CLI fallback for cleanup/overrides. Never clean identity fields in Python or mutate shared snapshots/process environment to handle a command. |
| GIX-22 | Missing API | The native Git directory is sufficient for the two fixed metadata leaves used here: `modules` and `COMMIT_EDITMSG`. Git's `path.c` applies no special relocation to either, including in linked worktrees. The adapter appends only these names to the canonical native Git directory. | No new binding is needed for these ordinary paths. Other `--git-path` names and symlinked metadata leaves retain CLI resolution; a general resolver must handle config/environment overrides, common/private storage and canonical targets. `Repository.modules_path()` means `.gitmodules`, not the `modules` storage directory. |
| GIX-23 | Missing API | No hook lookup or execution API is bound in GixPython 0.1.0. The removed absence fast path read config through Gix but used Python `os.stat()` to declare success. | Bind native hook lookup with configured/default path, linked-worktree, missing/nonexecutable-hook and diagnostic semantics, plus execution where needed. Until then all managed hook calls use Git, including `--ignore-missing` no-ops. A Python filesystem check is not a Gix implementation. |
| GIX-24 | Bug | In both object formats, `new_commit_as()` accepts a blob as the tree or a parent where `git commit-tree` rejects it. Tree-editor `upsert()`/`write()` accepts object IDs whose actual kinds disagree with blob/tree/gitlink modes; `git mktree --missing` rejects all three tested mismatches. `edit_references_as()` accepts a blob target under `refs/heads/`, rejected by `git update-ref`. | Provide checked commit/tree construction and reference edits, at least in Git-strict mode. Match Git's kind and direct-branch target validation before writing and under the required ref locks, including its distinct handling of symbolic aliases. Existing `_commit_tree`, `_write_tree` and `_update_ref` guards query Gix headers and select CLI on invalid inputs; they do not replace Gix writes with Python. |
| GIX-25 | Bug; missing API | After `git symbolic-ref refs/heads/dangling refs/heads/missing`, `Repository.references().all()` enumerates the dangling name, while `git for-each-ref --format=%(refname)` omits it. Valid symbolic aliases must remain present. Both SHA-1 and SHA-256 probes reproduce this difference. | Expose Git-compatible enumeration with the same dangling-reference and diagnostic behavior, retaining the raw iterator for callers that need it. `_for_each_ref` forces Gix to resolve symbolic targets and falls back to Git on failure; keep that fallback until a compatible Gix API/mode is verified. |

Windows reproduction for GIX-14 uses CPython 3.12.13, Git
2.55.0.windows.3 and the released GixPython 0.1.0 source distribution with
the same pinned Gitoxide revision above. Both `105114db` and the CLI metadata
batching change (`f6779dbb`) reproduce the following existing failures:

- `test_native_command_queries_match_cli` and
  `test_native_worktree_inventory_includes_bare_main` return backslashes in
  the adapter's native path text where Git returns forward slashes, in both
  object formats. The locations agree; the command-output formatting does not.
- The `commondir=b"\xff"` subtest of
  `test_repo_discovery_rejects_invalid_metadata` raises
  `RuntimeError: native worker panicked` instead of the CLI backend's
  `InvalidGitRepositoryError`. The binding must reject this input through its
  normal native error contract so discovery can take the existing fallback.

The adapters now format locations returned by `Repository.common_dir()`,
`workdir()` and `git_dir()` with the existing Windows-only path separator
conversion, including `Repo.common_dir` and gitfile worktree paths. Gix still
resolves every location. Ordinary, bare and linked repository metadata and
worktree-list queries compare exactly against Git without additional CLI
calls. POSIX filenames containing literal backslashes are unaffected.

Discovery catches only the binding's exact
`RuntimeError("native worker panicked")` and selects Git's existing validation
path. The malformed metadata regression then raises `InvalidGitRepositoryError`.
Unrelated runtime
errors still propagate. Both normal native write errors and worker panics
after a mutation begins are tested to ensure they never trigger a CLI retry.
GIX-14 remains open: these adapter changes do not fix the upstream panic or
the other discovery compatibility bugs.

The tests now pass gitfile operands in Git's Windows-compatible spelling and
compare symlink resolution against the current platform's Git output. Status
and ignore parity runs with a portable filename everywhere; only the extra
newline-filename variant is skipped on Windows. Blob-reference updates also
compare against Git: a direct branch rejects the blob, while a symbolic alias
outside `refs/heads/` accepts it on Git 2.55.0.windows.3, in both object
formats. That alias behavior is not evidence of a Gix mismatch and does not
invalidate GIX-24's separate direct-branch comparison.

For GIX-8, at fixture commit `44e0a8ec55c42559dfcdf5117710b26261a7c937`,
compare `git rev-list HEAD` with
`repo.rev_walk([repo.head_id()]).sorting("newest_first").all()`.
The first different IDs were Git's `5a53ae6d68e318a85be78fb5fcee4d3aa9dfbb48`
and gix's `ee854dcb62220adeae4feb59bd10185e7ac02957`.
Native walk builders return new values: retain the result of
`first_parent_only()` and other builder methods.

For GIX-15, compare `git blame --line-porcelain HEAD -- README.md` with
`repo.blame_file("README.md", repo.head_id(),
gix.BlameOptions(diff_algorithm="myers", rewrites=gix.Rewrites()))` at that same
fixture commit. The differing commits are
`2ddd5e5ef89da7f1e3b3a7d081fbc7f5c46ac11c` and
`3aacb3717ad78ec40e5b168a7ce8109aee6f156e`. `VERSION` and
`git/objects/commit.py` matched in the comparison.

For GIX-18, set `file diff=forced` in `.gitattributes`,
`diff.forced.binary=true`, and `diff.forced.textconv=false`. Change a NUL-containing
line in `file`: the native `to_git` cache reports one insertion and one removal,
while Git with `--no-textconv --numstat` reports `-\t-\tfile` (binary).

For GIX-24, use a repository containing an empty tree, a commit and a blob.
Pass the blob ID as the tree or a parent to `new_commit_as()` and compare
`git commit-tree BLOB` or `git commit-tree TREE -p BLOB`. Insert a commit ID
under the `blob` or `tree` kind with `Tree.edit().upsert()`, or a blob ID under
`commit`, then `write()`; Git's corresponding `mktree --missing` entry rejects
each mismatched kind. Finally, submit a `RefEdit.update_with_log()` for
`refs/heads/bad` with `Target.Object(blob_id)` and `PreviousValue.Any`;
`git update-ref refs/heads/bad BLOB` rejects that branch target.

The GIX-10 transaction probes start with HEAD pointing to `refs/heads/main`
at a first commit. Apply `RefEdit.update_with_log()` with `PreviousValue.Any`,
`LogChange.force_create_reflog=True` and a fixed message, comparing
`git update-ref --create-reflog -m MESSAGE`. Test advancing the branch, writing
its current target again, updating through a symbolic alias, and detaching HEAD
with `with_deref(False)` / `--no-deref`. Compare both the branch and HEAD logs,
including the previous OID, as recorded in the ledger.

The latest direct comparisons covered 12 cases in each of SHA-1 and SHA-256:
six object/branch type mismatches, identity cleanup, dangling enumeration and
four reflog transactions. Each case called Gix first and Git second. The local
probe and captured results are in
`.cache/gix-compatibility-ledger/{probe-contracts.py,contracts.json}`.
Existing [backend regressions](../test/test_gix_backend.py) protect the adapter
fallbacks, including `test_tree_writes_validate_child_object_kinds`,
`test_branch_blob_updates_match_git`,
`test_commit_identity_cleanup_matches_git` and
`test_reference_enumeration_preserves_aliases_and_skips_dangling_refs`.
This ledger update changes no runtime code or CLI budgets; the earlier
runtime validation and timings remain attributed to their measured snapshots.

### Remaining configuration reads (GIX-12)

The October 7 inventory identified 951 remote-enumeration reads, 674 actor
lookups, 262 remote-property reads, 202 tracking-branch lookups and 111 fetch
refspec checks. These are historical call-site counts, not additive savings.
The dedicated `.gitmodules` parser now covers supported submodule reads;
the other consumers still need generic config binding additions.

Local probes with official GixPython 0.1.0 and the existing CPython 3.12.14
confirmed these contracts against both GitPython backends:

| Consumer | GitPython behavior to preserve | Why the existing native API is insufficient |
| --- | --- | --- |
| Remote enumeration | Repository-local declaration order: `z-last`, `a-first` | `remote_names()` returned the merged, sorted `a-first`, `global-only`, `z-last`. |
| Remote URL/properties | The cached raw `url` property returned the last value, `../second`; `urls` yielded both `../first` and `../second`. | Native `Remote.url(Fetch)` selected only `../first`. Generic multivalue enumeration and raw snapshot semantics are still needed. |
| Actor lookup | A supplied file/stream reader returned `Reader Actor`, independent of the repository's `Repository Actor`. | Repository identity lookup cannot honor arbitrary source lists, reader snapshots, or GitPython's identity fallback rules. |
| Tracking branch | `branch.main.remote=z-last` and `merge=refs/heads/topic` produced `refs/remotes/z-last/topic`. | Native tracking lookup applied the configured fetch mapping and returned `refs/foreign/topic`. Replacing this API requires the original scalar config values. |
| Fetch refspec presence | The cached local reader tests whether a value exists before invoking fetch. | Native remote creation/refspec access applies URL/refspec parsing and merged configuration; it does not expose this raw, source-scoped presence check. |
| General config readers | Explicit files/streams, their order, included files, duplicate values and cached reader state | `ConfigFile` exposes only `boolean`, `integer`, `string`, `set_raw_value` and `to_bstring`. `OpenOptions.isolated()` also disables includes: a local included value read as `yes` through GitPython was absent natively. |

The needed additions are standalone generic parsing, ordered section/key and
multivalue access, source selection, and mutation/removal primitives. The
submodule adapter's conservative section guards can be removed once those
bindings exist. No generic configuration parser is implemented in Python.
The fixed general-config probe remains **2 CLI launches before and after**
this investigation; this item does not claim a process reduction.

## Other remaining operations

| Operation family | Why it still uses Git |
| --- | --- |
| `Repo.init`, clone | The different bundled initialization template set remains a Git compatibility bug; a compatible mode must reproduce Git's effective templates. Git's template/reinitialization options are not exposed. Clone also needs GitPython's environment, local-copy, progress and cleanup contracts. |
| Fetch, push, pull, remote pruning | Fetch outcomes do not expose the per-ref old IDs/status/notes needed for `FetchInfo`. Push/pull porcelain is absent. Network mutations cannot be retried after a partial native attempt. |
| Checkout, reset, index checkout/merge, move/remove | No bound equivalent of checkout-index/unpack-trees preserving these worktree/index semantics. Native tree/commit merge is a different operation. |
| Branch/tag porcelain and symbolic-ref mutation | Strict creation, reflogs, config movement, signing, message cleanup and safety contracts need more than a raw ref edit. |
| Object enumeration and alternate-directory listing | No binding for complete ODB object iteration or alternate-store enumeration; `cat-file --batch-all-objects` / `count-objects` remain. |
| Name-rev, trailer parsing, cherry | No equivalent bound operation. Native describe is not name-rev. |
| Config-backed remote/submodule maintenance | Missing config enumeration/multivar/removal operations (GIX-12), plus filesystem and worktree lifecycle requirements. |
| Hook execution | Every explicit hook request, including an absent hook, retains Git-managed lookup, execution and diagnostics until GIX-23 is addressed. Native operations retain GitPython's default hook/fsmonitor/maintenance restrictions. |

## Maintaining the adapters

`git/_backend.py` contains the capability checks. Managed command adapters return
the same bytes/text as the existing parser expects; direct adapters return the
existing GitPython object types. Keep operand validation before dispatch.

Gix APIs must provide Git behavior. Python glue may validate inputs, format
native results and select fallback; it must not implement missing Git semantics
or fabricate successful answers to lower CLI counts. Document missing or
unclear capabilities here and retain the CLI path until Gix provides them.
Name the actual Gix calls behind each conversion. Record every observed Git/Gix
mismatch as a compatibility bug with expected/actual behavior, version and a
reproduction or regression. A Gix-based workaround does not resolve that bug;
require an upstream fix or a verified mode as strict as Git before closing it.

Decide whether to fall back before mutating anything. Read/preparation failures
can use Git to preserve its public diagnostics. Once `_write()` begins,
`gix.Error` failures become `GitCommandError`; other exceptions propagate.
Neither may trigger a second CLI mutation.
Access native repository state through `Repo._get_gix_repository()` for bound
commands. Reuse is the default, with explicit recreation available; keep the
snapshot deviation and refresh behavior above documented. Close native iterators
when partially consumed.

Add each conversion with a no-subprocess check and a Git parity check where
practical, in its own commit. Update this ledger when a limitation changes;
the runtime report's reason should point to the corresponding entry.

## Windows validation

The [Python package workflow](../.github/workflows/pythonpackage.yml) adds a
Windows/Python 3.12 Gix job while preserving all 28 CLI combinations and their
existing check names. It installs `.[test,gix]`, verifies the selected backend
and runs the full suite
with the same coverage and pytest options. Every job retains JUnit results
and `--backend-report` operation counts under its `tests-OS-PYTHON-BACKEND`
artifact, and prints the 30 slowest test durations. The extra Gix job does not
duplicate the documentation build.

Local Windows checks use CPython 3.12.13, Git 2.55.0.windows.3 and GixPython
0.1.0 built from the released source distribution. The installed extension
matches the cached Windows ABI3 wheel byte-for-byte; that wheel's SHA-256 is
`1a0addd5f569e2ff7fb2b45c38be1093f6cabbead176c779533b983b86307dc2`.

The full baseline at `f6779dbb` reproduced all 17 failures described above:
16 ordinary failures and the subtest with malformed `commondir`. The full
patched suite passed with **1,760 tests and 40 subtests**, 58 skipped, nine
expected failures and three unexpected passes in 2,242.66 seconds. The three
unexpected passes and the path-deprecation warning also appeared in the
baseline. Ruff, mypy, basedpyright and the pinned pre-commit checks passed.

The baseline recorded 21,598 CLI launches in 2,279.10 seconds; the patched
run recorded 21,826 CLI launches and 86,936 native operations. Totals include the additional
regressions and tests that previously stopped at failing assertions. No CLI
ceilings were lowered. Both runs used isolated snapshots and CI's coverage,
Git configuration and pytest options. They overlapped, so the elapsed times
are not a controlled speed comparison. Logs, JUnit results and operation
reports are retained locally in `.cache/gix-windows/`.

The CLI repository/discovery regressions passed with 138 tests, 14 subtests,
nine skips and one expected failure. The changed native path, discovery,
reference and mutation-error cases also passed under Ubuntu WSL: 43 tests
and 14 subtests, using CPython 3.14.4, Git 2.53.0 and a separate released-source
GixPython build. This includes the POSIX newline-filename cases.

## Published release validation

The official Apple Silicon ABI3 wheel for GixPython 0.1.0 has SHA-256
`6b68758cb54a90c8eb893ac7815e74ccd9b48b197aaecec951366a6326168f52`.
It was downloaded from PyPI and verified against the published digest.
At the backend-selection commit, its SHA-1/SHA-256 smoke checks and fresh
extra-installation check passed (3 tests) on the existing CPython 3.12.14/macOS
environment. The dependency commit and all 31 descendants passed the fast QA
profile: Ruff lint/format, pre-commit, mypy, basedpyright, universal dependency
resolution, and fatal lint checks for the bundled dependencies. The full
published-wheel suite subsequently passed with coverage: 1,649 tests and
38 subtests passed, 79 skipped, and one expected failure, in 757.85 seconds
wall-clock on the same interpreter/platform. The performance notes above
record the tested revision and future optimization candidates.

## Historical local artifact validation

The original integration was validated with GixPython 0.1.0 from local checkout
`c8a9fabc03c326ad7b0afdf03d0bda4e62fdff52`, with Gitoxide revision
`f819565c2c4c56619c4888acef6cf3b8144cbccb` and its existing vendored fixes.
The ordinary Apple Silicon ABI3 wheel in `pygix/dist` has SHA-256
`62a03fe63e0e043c89f8271c10540cb00d31a15cf81fc1f45d3e2feb82a44e9f`.
The installed extension was compared byte-for-byte with that wheel.

Validation uses CPython 3.12.14 on macOS. The focused backend tests cover both
SHA-1 and SHA-256. Platform-specific skipped tests are not claims of validation
on other operating systems or free-threaded Python. The full suite and operation
report can be reproduced with the commands above.

| Check | Result |
| --- | --- |
| Full CLI installation | 1,360 passed, 80 skipped, 1 expected failure; 38 subtests passed. |
| Full GixPython installation | 1,396 passed, 79 skipped, 1 expected failure; 38 subtests passed. |
| Expanded native parity/fallback checks | 36 passed, including object-kind validation, identity cleanup, symbolic aliases/dangling refs, and compatibility-format guards. |
| Ruff lint/format, mypy, basedpyright | Passed. |
| Offline package build | Built an sdist and rebuilt its wheel; the archive includes `gix-requirements.txt` and the wheel declares the `gix` extra. |

The wheel directory also supported a fresh offline `.[test,gix]` installation.
The full installation test checks that its new environment selects the same
backend as the environment running the tests. Tox itself was not installed on
this machine; the underlying interpreter-based command was used directly.
