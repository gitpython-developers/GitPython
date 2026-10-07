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

Python extras add dependencies; they do not leave a runtime feature bit.
GitPython selects this backend when `gix` can be imported. Installing GixPython
separately therefore has the same effect. Use separate virtual environments to
compare the CLI and native installations. There is no backend environment
variable, constructor option, or runtime switch.

Git 2.52 or newer remains required. Unsupported operations and call options use
the existing CLI implementation. Public `repo.git.<command>()` calls retain
their command-line behavior. Native dispatch applies to library-managed calls.

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
wheels. A local GixPython source build is no longer required.

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
only fallback calls. The fixed warm benchmark instead isolates a user journey:
23 CLI launches versus one Gix launch, opening nine versus one, and nested
discovery eleven versus three after restoring the reference-format fallback
and sharing successful version checks.
The historical full-suite counts above predate this correction. A constant
`files` answer was not a Gix query; `GIX-1` records the missing binding.

| GitPython entry point / managed command | Native implementation | Remaining CLI cases |
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
| Reference enumeration, `for_each_ref` | Sorted reference names and literal prefixes, preserving symbolic aliases | Dangling symbolic refs, root refs, glob patterns, other formats/options |
| Managed `config --get KEY` | Merged repository config snapshot | Files/streams, enumeration, mutation; GIX-12 |
| Submodule enumeration and cached fields | Dedicated native `.gitmodules` parser over the existing worktree/blob source, with raw path/URL/branch values | Other/duplicate sections, ambiguous brackets, missing/implicit fields and parser errors; GIX-12 |
| Worktree inventory, `worktree list` | Main and linked worktree metadata, including bare main repositories and locks | Prunable entries; GIX-14 |
| `Repo.merge_base`, `Repo.is_ancestor` | Native graph queries for two revisions | Octopus/fork-point and other options |
| `Commit.count` | Reachable commit count, skip/limit/first-parent | Path filters and other revision options |
| `Commit.iter_items`, `Repo.iter_commits` | First-parent walks and a single tip | General history ordering; GIX-8 |
| Index entry reads, `ls_files` | Stage/mode/OID/path and exposed index flags | Custom and sparse indexes; GIX-3/4 |
| `IndexFile.version`, `update_index` query | Native index version | Actual `update-index` mutations |
| `IndexFile.write` and index persistence | Edit a private native index, publish through the existing lock | Custom, sparse, split, non-v2, unmerged, overlapping, or null-ID entries; GIX-3/4/13 |
| ODB `store`, managed `hash_object` | Native object hashing/writing with byte-fidelity preflight | Large/nonseekable input and changed serialization; GIX-2/5 |
| `IndexFile.write_tree` | Native tree editor with child-kind and null-ID validation | Missing non-gitlink children, invalid entries; GIX-7 |
| Tree serialization, `mktree` | Native tree editor with child-kind and null-ID validation | Missing children, unsupported or invalid entries; GIX-7 |
| Fresh index preparation, `read_tree` | Empty index or index from one tree | Existing index, merges, non-v2 selection; GIX-13 |
| `Commit.create_from_tree`, `commit_tree` | Explicit author/committer and unsigned UTF-8 commit | Identity cleanup, other encodings, signature formats, signing/options; GIX-6 |
| Reference log reads, `reflog` | Existence and GitPython's reflog format | Orphan logs, arbitrary formats, writes; GIX-10 |
| Committer identity, `var` | Native process/config identity from `Repository.committer()` | Per-command identity overrides, other variables and normalization/identity errors; GIX-21 |
| Selected `set_object` / reference deletion, `update_ref` | Native ref edits with GitPython's existing validation | Strict create/CAS, symbolic aliases other than HEAD, symbolic detachment, active-branch HEAD log, unchanged targets and log-message cleanup; GIX-9/10/21 |
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
`pyperf` harness and fixed GitPython 3.1.45 fixture. It measures eight public-API
operations and their complete journey on one already-open `git.Repo`, plus
separate direct opening and discovery from `git/objects`. Fresh high-level
wrappers preserve the cost of actual operations; imports, fixture preparation
and parity preflight are outside timing. Native repository refresh remains
inside operation timing, so these measurements include the cost of keeping
retained state current.

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
remain in place. Native repository ownership, invalidation and thread semantics
remain deferred as described above.

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

These are local findings, not filed issues. Some belong in the Python bindings;
others reflect Gitoxide behavior or deliberate differences from Git. References
below use the supplied `pygix` source and its pinned Gitoxide revision.

| ID | Finding and evidence | Needed before widening native coverage |
| --- | --- | --- |
| GIX-1 | Native config exposes `extensions.refStorage`; reading `HEAD` in SHA-1/SHA-256 reftable repositories raises `gix.Error` with an unsupported-storage cause. However, strict native opening plus a successful `HEAD` read accepts unknown version-1 extensions that Git rejects. It also accepts `extensions.refStorage=files` with repository version 0, which Git rejects. | Git-compatible repository-format/extension validation, typed native errors, and eventual reftable support. A dedicated format getter is not needed just to identify storage. Keep the CLI format query because it also validates the repository, with regressions for both the unsupported-HEAD signal and unknown extensions. |
| GIX-2 | Object lookup buffers full contents. `write_blob_stream` also reads its input into memory. | Bounded-memory object readers/writers usable by Python. The adapter currently caps native blob transfers at 8 MiB. |
| GIX-3 | Index bindings open the repository's index but cannot load an arbitrary existing index file. `set_path()` only chooses its write destination. | An index loader accepting a path, including relative-path semantics. |
| GIX-4 | Sparse index expansion is not exposed. | Expansion preserving skip-worktree and other metadata before editing. |
| GIX-5 | Structured-object writers may decode/re-encode supplied bytes. This is a compatibility guard, not a demonstrated corruption bug. | A raw-object writer, or a guaranteed byte-preserving contract. The current adapter checks the round trip in an in-memory ODB first. |
| GIX-6 | Native commit construction accepts a string message. GitPython also supports arbitrary message bytes and other declared encodings. | Byte-message commit construction with explicit encoding/signature semantics. |
| GIX-7 | Native tree editing requires existing non-gitlink child objects. Git's `mktree --missing` / `write-tree --missing-ok` permit missing children. | Missing-object tree construction with equivalent validation. |
| GIX-8 | General revision iteration differs from Git's default ordering. The same fixture enumerated 5,439 commits in both engines, with the first ordering difference at position 178. Its 1,923-commit first-parent chain matched. | A Git-compatible walk order; counts and first-parent walks already work. See the reproduction notes below. |
| GIX-9 | `PreviousValue.MustNotExist` accepts an existing ref already at the requested target. Native tests explicitly permit this; Git's strict create/CAS rejects it. | A strict native expectation, enforced under the same ref lock. A Python existence precheck would race. |
| GIX-10 | `LogChange` already sets the message, log mode and force-create flag for each ref edit. Its native writer preserves message whitespace: the direct regression stores `  keep\t  spaces  ` where Git stores `keep spaces`. Separately, active-branch HEAD logs, symbolic detachment and unchanged-target logging differ; `RefLog.Only` cannot express an independent arbitrary old OID. | A native message-normalization helper or policy for all ref edits, compatible HEAD/log policy and raw reflog append. `core.logAllRefUpdates` controls log creation, not cleanup. Canonical messages pass unchanged; cleanup cases fall back before mutation. Python must not normalize messages to repair native behavior. Symbolic aliases other than HEAD also retain CLI semantics. |
| GIX-11 | Inexact and ambiguous rename pairing/scores have not been established as Git-compatible. This is a conservative guard, not a claimed native bug. | Verified pairing, scoring, tie-breaking and option parity. Exact unambiguous renames are native. |
| GIX-12 | Generic config bindings lack standalone parsing, ordered section/key enumeration, multivars, unset/remove-section and source-scoped queries. Dedicated `.gitmodules` parsing is available and now used for supported submodule reads. | Those operations for `GitConfigParser` and remote/branch configuration. Native merged getters cannot replace repository-only config readers. |
| GIX-13 | Native index writing normalizes v4 to v2, offers no version setter, and expands split indexes. | Version and split-index preservation. Tests now assert that a split index remains split after an update. |
| GIX-14 | Gix correctly exposes linked worktree paths, including those of bare main repositories. Its documented `is_bare()` reflects configuration and can be true alongside a worktree; opening and inventory use both pieces of native metadata. Gitfiles are reopened at the canonical native Git directory, which also prevents an arbitrary gitfile location from becoming the worktree. Actual gaps remain: discovery tolerates undecodable HEADs and ignores dangling `commondir` symlinks, while Python flattens native failure kinds into `gix.Error`. | Opening forces native HEAD decoding and retains CLI validation for remaining layout/diagnostic gaps. Strict trust checks do not replace layout validation. Reopening uses the same strict options and returns actual native metadata; no upstream classification fix or Python worktree inference is needed. A native canonical-opening option could avoid the extra open later. |
| GIX-15 | Native blame disagrees with Git even with Myers and rewrite tracking selected. In the fixture's `README.md`, lines 150 and 158 are attributed to the opposite commits. Incremental order also differs. | Attribution and incremental-output parity before replacing `Repo.blame` / `blame_incremental`. |
| GIX-16 | Native archive streaming takes a tree rather than a commit. Its TAR omits Git's global PAX commit comment, leaves `export-subst` placeholders literal, and writes ordinary modes as `0644` where Git uses `0664`. | Commit-aware export substitution, metadata and permission parity. Both engines respected `export-ignore` in the probe. |
| GIX-17 | Revision parsing accepts abbreviated IDs with `-dirty`, prefers the OID suffix over an exact describe-shaped tag, and treats escaped braces in message searches differently. | Git-compatible revision grammar and regex semantics. Existing `test_rev_parse.py` cases reproduce all three. |
| GIX-18 | The tree-diff resource cache reads attributes from the index; Git also consults worktree attributes. Native binary classification with textconv configured can also differ even in `to_git` mode. | Independent attribute-source control and `--no-textconv` parity. Statistics currently fall back for any effective `diff` attribute. |
| GIX-19 | GixPython opens repositories with `extensions.compatObjectFormat`, but translation and object-write compatibility have not been validated. The installed Git reports `compatibility hash algorithm support requires Rust` when asked to translate an ID. This is an unvalidated capability guard, not evidence of missing native object mappings. | Verify compatibility-format reads, writes and OID translation against a Git build that supports them. All operations use CLI in the meantime. |
| GIX-20 | `Target.Symbolic(name)` validates full names but rejects standalone names accepted by `git check-ref-format --allow-onelevel`. Four of 430 audited calls differed: `refs` twice, `hellothere`, and `valid_one_level_refname`. Further probes include digits, punctuation and Unicode (`1`, `A1`, `HEAD_1`, `A-B`, `A.B`, `Ä`). | Expose Git-compatible partial/one-level name validation, or correct the native restriction where appropriate. This is a binding/behavior shortcoming to revisit upstream; standalone names rejected natively retain CLI validation. |
| GIX-21 | Native snapshot overrides for `committer.name`, `committer.email` and `gitoxide.commit.committerDate` resolve correctly. Applying them to the retained repository would expose command-specific identity to other threads. GixPython 0.1.0 has no general independent repository clone: Python `copy`/`deepcopy` fail, while the binding's internal `RepoHandle::clone()` shares its `Arc` state. | Bind a cheap independent native clone with isolated config so native identity resolution can apply per-command overrides, including removal semantics. Reopening isolates state but repeats setup; `with_object_memory()` also changes object-write behavior and is not a general clone API. Keep native process/config identity and CLI for differing command overrides. Do not mutate process environment/shared snapshots or resolve identity fields in Python. Explicit canonical commit inputs may still be adapted to `gix.Signature`. |
| GIX-22 | The native Git directory is sufficient for the two fixed metadata leaves used here: `modules` and `COMMIT_EDITMSG`. Git's `path.c` applies no special relocation to either, including in linked worktrees. The adapter appends only these names to the canonical native Git directory. | No new binding is needed for these ordinary paths. Other `--git-path` names and symlinked metadata leaves retain CLI resolution; a general resolver must handle config/environment overrides, common/private storage and canonical targets. `Repository.modules_path()` means `.gitmodules`, not the `modules` storage directory. |

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
| `Repo.init`, clone | Native initialization has a different bundled template set and does not expose Git's template/reinitialization options. Clone also needs GitPython's environment, local-copy, progress and cleanup contracts. |
| Fetch, push, pull, remote pruning | Fetch outcomes do not expose the per-ref old IDs/status/notes needed for `FetchInfo`. Push/pull porcelain is absent. Network mutations cannot be retried after a partial native attempt. |
| Checkout, reset, index checkout/merge, move/remove | No bound equivalent of checkout-index/unpack-trees preserving these worktree/index semantics. Native tree/commit merge is a different operation. |
| Branch/tag porcelain and symbolic-ref mutation | Strict creation, reflogs, config movement, signing, message cleanup and safety contracts need more than a raw ref edit. |
| Object enumeration and alternate-directory listing | No binding for complete ODB object iteration or alternate-store enumeration; `cat-file --batch-all-objects` / `count-objects` remain. |
| Name-rev, trailer parsing, cherry | No equivalent bound operation. Native describe is not name-rev. |
| Config-backed remote/submodule maintenance | Missing config enumeration/multivar/removal operations (GIX-12), plus filesystem and worktree lifecycle requirements. |
| Hook execution | Explicitly requested hooks retain the existing Git-managed behavior. Native operations retain GitPython's default hook/fsmonitor/maintenance restrictions. |

## Maintaining the adapters

`git/_backend.py` contains the capability checks. Managed command adapters return
the same bytes/text as the existing parser expects; direct adapters return the
existing GitPython object types. Keep operand validation before dispatch.

Gix APIs must provide Git behavior. Python glue may validate inputs, format
native results and select fallback; it must not implement missing Git semantics
or fabricate successful answers to lower CLI counts. Document missing or
unclear capabilities here and retain the CLI path until Gix provides them.

Decide whether to fall back before mutating anything. Read/preparation failures
can use Git to preserve its public diagnostics. Once `_write()` begins, native
errors become `GitCommandError` and must never trigger a second CLI mutation.
Access native repository state through `Repo._get_gix_repository()` for bound
commands. Reuse is the default, with explicit recreation available; keep the
snapshot deviation and refresh behavior above documented. Close native iterators
when partially consumed.

Add each conversion with a no-subprocess check and a Git parity check where
practical, in its own commit. Update this ledger when a limitation changes;
the runtime report's reason should point to the corresponding entry.

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
