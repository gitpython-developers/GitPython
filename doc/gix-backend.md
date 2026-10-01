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

| GitPython entry point / managed command | Native implementation | Remaining CLI cases |
| --- | --- | --- |
| `Git.get_object_header`, ODB `info` | Object resolution and native header lookup | Custom storage, unsupported revision grammar |
| `Git.stream_object_data`, ODB `stream` | Object bytes in an independent stream | Objects larger than 8 MiB; GIX-2 |
| `Repo.rev_parse`, `rev_parse` metadata queries | Revision lookup, common directory, object format, bare flag, worktree root | Reference-storage format query; initial repository validation; message searches and describe forms; GIX-1/14/17 |
| Tree enumeration, `ls_tree` | Native tree entries with modes, names, and object IDs | Other command options |
| Symbolic reference lookup, `symbolic_ref` | Nonrecursive target lookup | Mutation, missing-reference diagnostics |
| Reference enumeration, `for_each_ref` | Sorted reference names and literal prefixes, preserving symbolic aliases | Dangling symbolic refs, root refs, glob patterns, other formats/options |
| Managed `config --get KEY` | Merged repository config snapshot | Files/streams, enumeration, mutation; GIX-12 |
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

All native operations currently fall back for reftable (GIX-1) and repositories
with `extensions.compatObjectFormat` (GIX-19). Process-returning calls, timeouts,
custom storage/environment, global Git options, and unhandled command options
also retain their CLI contracts. A broken installed extension is reported as
an import error; only an absent top-level `gix` selects CLI mode.

## Future performance work

These runtime and fixture optimizations have not been implemented. The local
measurements use official GixPython 0.1.0 and existing CPython 3.12.14 on macOS
arm64 at `89c609cf92335e75652d7725682e215a9ea080e5`.

The full suite with coverage took 757.85 seconds wall-clock (757.04 seconds
reported by pytest): 1,649 tests and 38 subtests passed, 79 skipped, and one
expected failure. Operation reporting counted 114,800 native operations and
39,002 CLI fallback decisions. Those decisions are not a complete subprocess
count: raw `repo.git` calls and subprocesses started by Git are not all counted.

### Retain native repository state

`git._backend._repository()` calls `gix.open_opts()` for every operation;
`git.Repo` does not retain a native repository. This deliberately avoids stale
configuration and storage views after CLI mutations, but also loses native
state reuse. In a 1,000-call benchmark without coverage, an object read using
one native handle took 0.046 ms per call, compared with 0.635 ms through the
current stream adapter. Opening and validating a native repository alone took
0.418 ms per call. These are small repeated-read measurements, not an estimate
of whole-suite speedup.

Consider retaining native repository/object-store state per `git.Repo`, with
explicit ownership, `close()` behavior, thread semantics, and invalidation for
CLI/native mutations, configuration changes, and environment overrides.
Preserve the current safety checks and diagnostics. Establish those contracts
before replacing the fresh-open policy below.

### Reuse prepared test fixtures

A 19-case submodule rejection sample without coverage took 15.62 seconds:
1,258 `Git.execute()` calls accounted for 11.86 seconds, while 1,995 native
repository-open/validation attempts accounted for 0.84 seconds. Most work was
fixture setup. This sample supports prioritizing repeated setup subprocesses;
it is not a profile of the entire suite.

Collection found 1,729 parameterized cases from 703 distinct source bodies.
Source inspection identified the following conservative set of 422 cases whose
assertions do not require changing repository state after preparation. The
remaining cases have not been exhaustively classified; these are reuse
candidates, not proof that a shared fixture is safe in every execution order.

| Cases | Current setup | Future opportunity |
| --- | --- | --- |
| 166 | `TExc` (157) and `TestActor` (9) inherit repository-building `TestBase`. | Use a base without repository setup; these assertions need no repository. |
| 182 | Three submodule rejection bodies repeatedly build `movable_submodule`, then check snapshots for no mutation. | Share one committed baseline, with fresh Python wrappers and per-case temporary paths. |
| 51 | Six submodule rejection bodies prepare nested metadata, separate metadata, intermediate/leaf symlinks, or retained metadata before checking rejection. | Prepare immutable variants once; group by layout rather than repeating setup for every operation or spelling. |
| 15 | Eight revision-query bodies rebuild the same four-commit graph, refs, index, and reflogs through `rev_parse_repo`. | Share the prepared graph; keep the five mutating cases isolated. |
| 8 | Tree lookup bodies clone and check out `0.3.2.1` through `with_rw_repo`. | Share one prepared historical repository; the assertions only read trees. |

Thus at least 256 repository-using cases are initial sharing candidates,
alongside 166 cases where repository setup could disappear. They could
plausibly use about 14 prepared scenarios: one ordinary submodule baseline,
11 rejection-layout variants, one revision graph and one historical tree
baseline. That scenario count is an implementation estimate, not validated
fixture sharing. The full
`movable_submodule` fixture is constructed for 322 cases and `local_submodule`
for 68 cases. Even mutating cases could start from prepared filesystem copies,
with writable refs, index, config, worktree and submodule metadata isolated;
their shared object data and source repositories must remain immutable.
Snapshot/copy cost and path relocation need measurement before choosing a
strategy. Do not hard-link mutable Git metadata or rely on resetting only
`HEAD` to restore a fixture.

Additionally, all 25 collected `TestBase` classes reconstruct both historical
dependency repositories, including checkouts and `git gc`: 50 constructions.
Only four classes call the dependency-source helpers. Lazily preparing two
immutable sources once per session could remove 48 of those constructions,
independently of whether the consuming tests mutate their own repositories.

Before widening fixture scope, verify that each candidate preserves refs,
reflogs, index, configuration, worktree, metadata and source state; distinguish
harmless cache changes from persistent changes. Keep mutable Python wrappers,
environment patches and temporary paths isolated. Security rejection tests
must retain their no-side-effect assertions and pristine starting state, so
an earlier failure cannot contaminate later results. Profile setup/call/teardown
and compare warmed runs before claiming a suite-wide improvement.

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
| GIX-12 | Config bindings lack standalone parsing, ordered section/key enumeration, multivars, unset/remove-section and source-scoped queries. | Those operations for `GitConfigParser` and remote/branch configuration. Native merged getters cannot replace repository-only config readers. |
| GIX-13 | Native index writing normalizes v4 to v2, offers no version setter, and expands split indexes. | Version and split-index preservation. Tests now assert that a split index remains split after an update. |
| GIX-14 | Gix correctly exposes linked worktree paths, including those of bare main repositories. Its documented `is_bare()` reflects configuration and can be true alongside a worktree; inventory now uses both pieces of native metadata. Actual gaps remain: discovery tolerates undecodable HEADs and ignores dangling `commondir` symlinks, while Python flattens native failure kinds into `gix.Error`. | Explicit native HEAD decoding and CLI fallback for remaining layout/diagnostic gaps. Strict trust checks do not replace layout validation. Canonical paths can be supplied when reopening through Gix, as already done for the inventory's main repository; no classification fix is required upstream. Initial `--resolve-git-dir` stays with Git at this stage. |
| GIX-15 | Native blame disagrees with Git even with Myers and rewrite tracking selected. In the fixture's `README.md`, lines 150 and 158 are attributed to the opposite commits. Incremental order also differs. | Attribution and incremental-output parity before replacing `Repo.blame` / `blame_incremental`. |
| GIX-16 | Native archive streaming takes a tree rather than a commit. Its TAR omits Git's global PAX commit comment, leaves `export-subst` placeholders literal, and writes ordinary modes as `0644` where Git uses `0664`. | Commit-aware export substitution, metadata and permission parity. Both engines respected `export-ignore` in the probe. |
| GIX-17 | Revision parsing accepts abbreviated IDs with `-dirty`, prefers the OID suffix over an exact describe-shaped tag, and treats escaped braces in message searches differently. | Git-compatible revision grammar and regex semantics. Existing `test_rev_parse.py` cases reproduce all three. |
| GIX-18 | The tree-diff resource cache reads attributes from the index; Git also consults worktree attributes. Native binary classification with textconv configured can also differ even in `to_git` mode. | Independent attribute-source control and `--no-textconv` parity. Statistics currently fall back for any effective `diff` attribute. |
| GIX-19 | GixPython opens repositories with `extensions.compatObjectFormat`, but translation and object-write compatibility have not been validated. The installed Git reports `compatibility hash algorithm support requires Rust` when asked to translate an ID. This is an unvalidated capability guard, not evidence of missing native object mappings. | Verify compatibility-format reads, writes and OID translation against a Git build that supports them. All operations use CLI in the meantime. |
| GIX-21 | Native snapshot overrides for `committer.name`, `committer.email` and `gitoxide.commit.committerDate` resolve correctly. Applying them to the retained repository would expose command-specific identity to other threads. GixPython 0.1.0 has no general independent repository clone: Python `copy`/`deepcopy` fail, while the binding's internal `RepoHandle::clone()` shares its `Arc` state. | Bind a cheap independent native clone with isolated config so native identity resolution can apply per-command overrides, including removal semantics. Reopening isolates state but repeats setup; `with_object_memory()` also changes object-write behavior and is not a general clone API. Keep native process/config identity and CLI for differing command overrides. Do not mutate process environment/shared snapshots or resolve identity fields in Python. Explicit canonical commit inputs may still be adapted to `gix.Signature`. |

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

## Other remaining operations

| Operation family | Why it still uses Git |
| --- | --- |
| `Repo.init`, clone | Native initialization has a different bundled template set and does not expose Git's template/reinitialization options. Clone also needs GitPython's environment, local-copy, progress and cleanup contracts. |
| Fetch, push, pull, remote pruning | Fetch outcomes do not expose the per-ref old IDs/status/notes needed for `FetchInfo`. Push/pull porcelain is absent. Network mutations cannot be retried after a partial native attempt. |
| Checkout, reset, index checkout/merge, move/remove | No bound equivalent of checkout-index/unpack-trees preserving these worktree/index semantics. Native tree/commit merge is a different operation. |
| Branch/tag porcelain and symbolic-ref mutation | Strict creation, reflogs, config movement, signing, message cleanup and safety contracts need more than a raw ref edit. |
| Object enumeration and alternate-directory listing | No binding for complete ODB object iteration or alternate-store enumeration; `cat-file --batch-all-objects` / `count-objects` remain. |
| Name-rev, check-ref-format, trailer parsing, cherry | No equivalent bound operation. Native describe is not name-rev. Existing validation and parsing remain shared by both installations. |
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
Open a fresh native repository for each operation so CLI fallback cannot leave
a cached native view stale. Close native iterators when partially consumed.

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
