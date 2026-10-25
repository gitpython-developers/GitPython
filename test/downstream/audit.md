# GitPython downstream compatibility audit

## Known incompatibilities

The October 22–23, 2026 audit covered 115 projects on both CLI and Gix backends
of the unreleased migration. These incompatibilities are relative to released
GitPython **3.2.1**; passing selections do not close them.

### Read-only index entries

`IndexFile.entries` is an immutable `(path, stage)` snapshot. Readers used by dlt
and Renku can read these snapshots; dictionary mutation is unsupported. Callers that
write entries directly must use supported index operations. This is an intentional
API break, not a demonstrated Gitoxide bug; the audit does not count an untested writer as passing.

### sbxloop: constructor validation precedes subclass configuration readers

sbxloop **2.1.36** retains **five upstream failures** that pass with released GitPython.
Its `_MetadataRepo.config_reader()` override previously controlled constructor parsing.
Git/Gix discovery now rejects malformed includes/configuration and version-0 storage
extensions before that override runs, changing custom exceptions and diff expectations.
The subclass must prepare its trusted metadata view before opening it and handle
native discovery errors. Required validation is retained; these failures remain open.

### Kas: creating empty configuration sections

Kas **5.5** retains **three upstream SSH-key failures** that pass with released GitPython.
It calls `add_section('gpg "ssh"')` before assigning `allowedSignersFile` through a proxy.
The available Git/Gix config edit APIs do not create empty sections, and the inherited
ConfigParser section API was removed. Callers can use
`set_value('gpg "ssh"', 'allowedSignersFile', path)` directly. Nonempty section
assignment is supported; empty-section support is a missing capability/API break.

### Mistral Vibe: repository finalization timing

Mistral Vibe **3.0.1** retains **one upstream failure** out of its 1,359-case selection:
`test_refuses_a_bare_repository_without_stranding_the_open` counts `Repo.close()` calls
before garbage collection. Both implementations call it again during finalization,
but a reference cycle delays the released version's second call. The branch exposes
that timing assumption sooner. No reference cycle was added to hide the difference;
the unchanged test remains failing on both backends.

### Airflow: ambiguous mirror-fetch results

Airflow Git provider **1.0.1** retains **two supplemental failures** when a branch and
tag share a name. Both refs update, but this branch omits the ambiguous branch result;
released GitPython returns a nonexistent `refs/remotes/main` whose commit is unreadable.
Both fail the real-repository check, with different decoding defects. This is a
GitPython adapter gap; Git's `fetch --porcelain` exposes full destination identities.
Fetch remains a CLI fallback pending a result adapter/GixPython outcome with matching semantics.

The [backend ledger](../../doc/gix-backend.md) records the API breaks, missing APIs,
Git compatibility bugs and affected fallbacks separately. These audit results do not close upstream bugs.

## Other retained failures

These reproduce with released GitPython or are separately identified harness limits.
They are not folded into the incompatibility counts above or reported as passing.

| Project | Retained outcome | Cause / boundary |
| --- | --- | --- |
| Plato SDK 2.181.0 | 1 failure | Off-FUSE helper passes `separate_git_dir` without `allow_unsafe_options=True`; the existing safety guard rejects it. |
| SDMX 2.28.0 | 1 failure | Fetch updates the remote but downstream refresh does not advance the existing local branch. |
| ComfyUI Manager 4.3 | 4 failures | Three fake repositories omit the called `list_heads()` API; a timestamp assertion rejects `_1` even when it denotes the current hour. |
| Demisto SDK 1.39.13 | 1 failure | Root listing passes `.` to tree lookup, catches `KeyError`, and returns an empty list. |
| Airbyte Internal Ops 0.126.5 | 2 failures | Fixed-component path parsing returns `third-party` instead of the nested connector name. |
| Dstack 0.22.5 | 1 failure | `_get_repo_default_branch()` truncates `feature/nested` to `nested`. |
| Diffusers 0.41.0 | Separate reproduction; outside counted cases | `get_doctest_files(diff_with_last_commit=True)` raises its own `UnboundLocalError` for `upstream_main`; four supplemental cases pass. |
| sbxloop 2.1.36 | 10 additional outcomes | One local-submodule refusal assertion also fails with the release; eight upstream LFS fixtures hide the supplied binary with a hardcoded `PATH`; one bounded supplemental bad-token retry times out. |

sbxloop's timeout is not evidence that its own error would eventually be correct or
incorrect. Four other real LFS/helper supplements pass. Its five branch incompatibilities
are separate from these ten outcomes. Initial dependency, fixture and quota errors
were kept separately from corrected final runs; source expectations were unchanged.

## Verified compatibility

The commits identify unreleased development revisions used to verify these contracts.
Counts are the recorded audit results, rather than a new run of these downstreams
against the current branch head.

| Commit | Affected caller / verified behavior |
| --- | --- |
| `b3a4ba8d` | dlt/Renku: support immutable `IndexFile.entries` readers, including merge stages; writers are unsupported. |
| `2fd0d008` | Mistral Vibe: respect global `-C` despite automatic `GIT_DIR`/`GIT_WORK_TREE`; preserve explicit environment precedence. The 22 affected cases pass, with staging isolated from the original dirty checkout. |
| `8ce71f5c` | Mistral Vibe: preserve checkout context for separate Git directories; two staging cases pass using Git/Gix-resolved worktree metadata. |
| `97921e3e` | Aider: accept `git.GitDB`/`git.db.GitDB` as selectors for managed `GitCmdObjectDB`; all 21 repository tests pass. |
| `8877d095` | Angr: resolve branches tracking another local branch through Git's upstream resolver; five real checks pass. Released GitPython also had this bug; the operation retains a CLI fallback. |
| `44403026` | MCP Server Git: preserve root-tree paths and missing-component `KeyError` diagnostics; three focused regressions and the complete 186-test selection pass. |
| `47a668ce` | sbxloop: accept explicit `expand_vars=False` in its original constructor position; 91 affected cases pass. Paths are literal and `True` rejects automatic expansion. |
| `2d84a6ae` | Salt: resolve the editable/source `git.__version__` from `VERSION`; provider detection and 34 unchanged tests pass. |
| `a88e46a4` | Packaging: keep that source-only version fallback inactive in wheels; isolated installation profiles pass. |
| `617a0586` | Demisto SDK: retain the explicit `typing.Union` import from `git`; validator registration and 25 upstream tests pass. |
| `5749f6db` | Kas: support nonempty config section assignment through Git config remove/set operations; 11 real supplements pass. Values are validated first; replacement is not transaction-wide atomic. |
| `3640db47` | MkDocs RSS Plugin: retain the explicit `typing.Optional` import from `git`; five upstream and ten supplemental cases pass. |

Scripted regressions in [test_downstream_compatibility.py](../test_downstream_compatibility.py)
cover SHA-1/SHA-256, files/reftable, index snapshots, revision paths, linked worktrees,
explicit environments, literal paths, and separate Git directories. Config and
installation regressions cover section assignment, typing imports and source versions.
Git/Gix retain ownership and input validation.

## Selection, method and recorded totals

The [PyPI download snapshot](https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json)
was updated **2026-10-01 12:40:51 UTC** and ranks September downloads. All identified
current declared GitPython consumers in its top **15,000 distributions** were processed,
including runtime, optional, development and documentation extras. Known Git-focused
and undeclared users were added; this is not a strict popularity top 115.
Overlapping `sbxloop-worker`/`skypilot-nightly` distributions were excluded.
Three metadata records returned 404 (`aaaaaaaaa`, `vnai`, `vnstock`); no consumer status was inferred.

Identified ranked declarations account for **348,530,835** distribution downloads;
base requirements account for **87,447,036**. The audit covers 100% of each identified
inventory, not all GitPython installations, historical/undeclared users, or projects
below the **53,155-download** snapshot cutoff. Downloads are requests, not unique users.

Runs used released downstream code and isolated editable GitPython environments on
Linux aarch64: Git **2.53.0**, GixPython **0.2.0**, uv **0.13.5**, Python **3.12.15**.
Renku and Mongo Tooling Metrics used Python 3.11; sbxloop used 3.13.17.
Archive digests/release identities were verified in the original audit. Private Git
configuration and cleared inherited Git/Python/pytest settings isolated fixtures.
CLI ran before Gix; `git.__file__` and backend checks proved the intended import.
Released 3.2.1 baselines were force-reinstalled and verified in site-packages.

Unchanged upstream tests retain their mocks and helper cases. Labeled supplements
execute unchanged callers with real repositories; exact helper AST isolation, whole-module
imports, local URL rewrites and non-Git service boundaries are disclosed in the inventory.
Native means execution through supported GixPython `gix` APIs. Selecting Gix may
still invoke documented CLI fallbacks; pass counts are not native coverage measurements.
Unrelated models, clouds, databases, EDA builds, private credentials and external publishing were outside scope.

Counts are **per backend**; final CLI/Gix selections match. `U` means upstream passes,
`S` supplemental passes/checks, `F` retained failures, and `K` skips. First-batch `S`
includes Tach's seven and scmrepo's nine direct assertions, not additional pytest cases.
scmrepo additionally has two non-strict XPASS, not included in `U`. No skip or unused
declaration is counted as a pass; nine projects have zero tests.

| Selection | Projects | U | S | F | K |
| --- | ---: | ---: | ---: | ---: | ---: |
| First batch, October 22 | 31 | 3,614 | 128 | 1 | 41 |
| Second batch, October 22 | 30 | 1,172 | 177 | 21 | 6 |
| Third batch, October 22 | 39 | 754 | 378 | 8 | 0 |
| Fourth batch, October 23 | 15 | 117 | 187 | 1 | 2 |

Historical full GitPython suites after the last audit fix passed **1,832 / 162 skipped /
one xfailed** on CLI and **1,934 / 60 skipped / one xfailed** on Gix, with **59 passed
subtests** each. Ruff lint/format, relevant mypy, fixture ShellCheck, installation
profiles and diff whitespace checks passed at their recorded scope. The fourth batch
changed no production code and reused those results. This consolidation reruns neither
those suites nor the 115 downstream audits; later branch changes have their own validation.

## Project inventory

### First batch: major consumers and known Git-focused users

| Distribution | Release | U | S | F | K | Selected coverage and limits |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| transformers | 5.20.2 | 24 | 4 | 0 | 2 | Real test selection/diffs and checkout; 2 existing inference skips. |
| cyclopts | 5.3.0 | 0 | 2 | 0 | 0 | Unchanged Sphinx configuration and source links; no upstream Git tests. |
| pylint | 4.1.3 | 8 | 7 | 0 | 0 | Upstream Repo mocks; real primer clone/fetch/checkout and release helper checks. |
| langchain-community | 0.4.2 | 2 | 0 | 0 | 0 | Real GitLoader clones, checkout, trees and ignored paths; manually installed integration. |
| mlflow-skinny | 3.17.2 | 53 | 0 | 0 | 0 | 53 unique upstream project/context/versioning cases; some Repo mocks. |
| bandit | 1.9.4 | 12 | 0 | 0 | 0 | Real baseline repositories; 2 error-path mocks. |
| swebench | 5.0.2 | 0 | 4 | 0 | 0 | Real AutoContextManager; no caller tests upstream; BM25/Java helpers untested. |
| bottleneck | 1.6.0 | 0 | 6 | 0 | 0 | Real announcement/contributor Git queries; offline GitHub metadata boundary. |
| diffusers | 0.41.0 | 0 | 4 | 0 | 0 | Real unchanged tests_fetcher helpers; separate upstream Python bug reproduced. |
| acryl-datahub | 1.7.0.16 | 8 | 0 | 0 | 1 | Public HTTPS/local clones and SSH timeout; private SSH credential skip. |
| dlt | 1.31.0 | 106 | 0 | 0 | 3 | Real init/update/deploy/workbench/dbt Git paths; private-key skips; index bug fixed. |
| mistral-vibe | 3.0.1 | 1358 | 0 | 1 | 0 | 1,359 upstream cases: 1,358 pass, one GC assertion fails; 24 compatibility failures fixed. |
| tach | 0.35.3 | 18 | 7 | 0 | 0 | Upstream Git/pytest-plugin tests; 7 additional branch-info assertions (not pytest cases). |
| checkov | 3.3.30 | 38 | 10 | 0 | 0 | Upstream mostly mocks; real GitGetter clones and incremental history checks. |
| jupytext | 1.19.6 | 30 | 0 | 0 | 0 | Complete pre-commit suite: real index commits/hooks/notebook execution, including Pandoc. |
| crewai-tools | 1.15.28 | 0 | 0 | 0 | 0 | Declared github extra, but no released GitPython caller or test exists. |
| openmed | 3.0.0 | 0 | 0 | 0 | 0 | No direct GitPython imports; docs revision plugin separately audited. |
| kedro | 1.7.0 | 299 | 6 | 0 | 0 | Complete starters suite; GitPython calls mocked; real ls_remote supplemental checks use CLI. |
| scmrepo | 3.6.2 | 124 | 9 | 0 | 19 | 71 passing explicit GitPython cases; 2 additional XPASS; 9 direct backend assertions. |
| dagster-dbt | 0.29.26 | 6 | 4 | 0 | 0 | Upstream clone mocks; real project-manager clones and dbt deps/parse. |
| python-semantic-release | 10.7.0 | 873 | 0 | 0 | 0 | 207 units + 662 workflows + 4 real-remotes upstream cases; HTTP/release mocks retained. |
| pydantic-ai-skills | 2.1.0 | 32 | 12 | 0 | 0 | Upstream Git registry mocks; real clone/pull/sparse-checkout registry checks. |
| skypilot | 0.14.1 | 91 | 10 | 0 | 0 | Upstream command mocks/direct subprocesses; real ls_remote supplements use CLI. |
| mkdocs-git-revision-date-localized-plugin | 1.6.0 | 55 | 0 | 0 | 6 | Real MkDocs builds (36 passes); 19 helpers; 6 intentional timeago JS skips. |
| ragas | 0.4.3 | 10 | 13 | 0 | 0 | Upstream mocked/helpers; real version_experiment staging/commit/dirty checks. |
| appworld | 0.1.3.post1 | 0 | 6 | 0 | 0 | No released callers; 6 real preflight tests of explicitly identified main development script. |
| pydriller | 2.12 | 312 | 0 | 0 | 0 | Complete upstream suite; separately enabled memory case also passes (3 x 704 commits). |
| nbdime | 4.0.4 | 87 | 7 | 0 | 10 | Git refs/filter/driver/web/server tests; 10 notebook fixture skips; 4 Mercurial cases excluded. |
| mkdocs-git-committers-plugin-2 | 2.5.0 | 0 | 5 | 0 | 0 | No upstream tests; real history/dates/cache/submodules with local HTTP fixture. |
| renku | 2.9.4 | 66 | 3 | 0 | 0 | Real repository/init/gitignore paths and wrapper checks; 11 external cases deselected. |
| gitup | 0.5.2 | 2 | 9 | 0 | 0 | 2 weak upstream CLI/bookmark cases; real update.py fetch/fastforward/dirty/diverged checks. |

### Second batch: next declared consumers

| Distribution | Release | U | S | F | K | Selected coverage and limits |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| mosaicml-streaming | 0.13.0 | 0 | 4 | 0 | 0 | Docs commit SHA helper; exact unchanged AST function isolated from Torch/Pandoc imports. |
| feu | 0.8.4 | 26 | 3 | 0 | 3 | 3 real upstream Git integrations, 23 mocks/import cases; real clone/metadata supplements; 3 missing-Git skips. |
| snowflake-cli | 3.30.0 | 13 | 15 | 0 | 0 | Upstream Git check mocked; real template clone/dirty/error supplements. |
| plato-sdk-v2 | 2.181.0 | 0 | 11 | 1 | 0 | Real released Git/transport helpers; off-FUSE unsafe-option failure also occurs with released GitPython. |
| powertrain-build | 1.19.0 | 24 | 4 | 0 | 0 | Real repository diffs and submodule SHAs; release clone parent fetched for HEAD~1 fixture. |
| cosmic-ray | 8.7.0 | 0 | 5 | 0 | 1 | Upstream Git test is a TODO skip; real unchanged git-filter caller supplements. |
| segmentation-models-pytorch | 0.5.0 | 0 | 8 | 0 | 0 | Test selector Git function/constants isolated unchanged by AST; Torch/model suite omitted. |
| frappe-bench | 5.31.0 | 4 | 7 | 0 | 0 | Real Git utilities and branch switching; Frappe services omitted. |
| pygount | 3.2.0 | 10 | 5 | 0 | 0 | Real clone/scanning/tag/error/cleanup; SSH fixture routed through HTTPS. |
| openhands-aci | 0.3.3 | 0 | 0 | 0 | 0 | Unused declared dependency: no GitPython caller or GitPython test in release. |
| newton | 1.7.0 | 37 | 0 | 0 | 0 | 15 Git asset sparse-download/cache/concurrency cases and 22 filesystem helper cases. |
| aider-chat | 0.86.2 | 21 | 0 | 0 | 0 | Complete upstream repository suite with real Git; model mocks retained; GitDB selector fixed. |
| openhands-ai | 1.11.0 | 0 | 0 | 0 | 0 | Unused declared dependency; all 227 release Python files match tag; no GitPython imports. |
| angr | 10.0.4.post1 | 0 | 5 | 0 | 0 | Unchanged standalone bug-report module; real repository states; local tracking fixed; binary-analysis stack omitted. |
| rsl-rl-lib | 5.5.1 | 0 | 6 | 0 | 0 | Exact unchanged Logger._store_code_state method isolated by AST; no Torch training. |
| git-me-the-url | 2.2.0 | 0 | 9 | 0 | 0 | Real public API/CLI/remote URL/detached ancestry; unrelated Bitbucket translator gap. |
| edk2-pytool-library | 0.23.17 | 3 | 8 | 0 | 0 | Real clone/submodule upstream fixture and helper supplements; historical source SHA/URL rewrite retained. |
| pydeseq2 | 0.5.4 | 0 | 7 | 0 | 0 | Full unchanged docs configuration via runpy; actual released package; linked/bare/SHA256/unborn repositories. |
| sdmx1 | 2.28.0 | 1 | 4 | 1 | 0 | One upstream case uses real Git session setup; real fetch supplements; existing-checkout refresh failure also released. |
| comfyui-manager | 4.3 | 65 | 9 | 4 | 0 | Complete wrapper/helper selection includes pygit2/pure/mocked cases; 4 helper-test defects also released; real helper supplements. |
| socketsecurity | 2.11.3 | 32 | 8 | 0 | 0 | Real CI/diff/shallow-fetch/commit-context cases plus mocks; real supplements; Socket API omitted. |
| snakemake | 9.27.1 | 19 | 14 | 0 | 1 | One real upstream bare clone/show case, 18 adaptation/mock cases; real source-cache/helper supplements; no-conda skip. |
| edk2-pytool-extensions | 0.31.3 | 55 | 1 | 0 | 1 | Real resolver/dependency/setup/worktree tests; actual historical fixture repositories; recursive supplement; 1 Windows skip, 1 large firmware case excluded. |
| openmetadata-ingestion | 2.0.6.0 | 17 | 7 | 0 | 0 | 17 upstream clone mocks/helpers; 7 real credential-URL clone/overwrite/error checks of full unchanged Looker module; warehouses omitted. |
| siliconcompiler | 0.38.11 | 264 | 8 | 0 | 0 | Resolver/updater/issue suite includes clones/metadata plus many mocks; real clone/checkout/cache/submodule/version supplements; EDA tools omitted. |
| pyats-reporter | 26.9 | 0 | 9 | 0 | 0 | Actual closed-source Cython get_git_info helper on real repositories; verified aarch64 wheel; no public source or upstream suite. |
| zenml | 0.98.0 | 3 | 16 | 0 | 0 | 3 upstream CodeArchive mocks; 16 real clone/repository-context/archive checks; onboarding/Jupyter and ML pipelines omitted. |
| mcp-server-git | 2026.10.19 | 186 | 0 | 0 | 0 | Complete unchanged server/protocol/eras/entrypoint suite; real Git tools and protocol calls; 3 revision-path regressions pass. |
| cruft | 2.16.0 | 182 | 0 | 0 | 0 | Complete API/CLI/utilities selection with real template clones, recursive submodules and updates; subprocess display abbreviation normalized. |
| sbxloop | 2.1.36 | 210 | 4 | 15 | 0 | 224 upstream cases: 210 pass, 5 remaining compatibility failures, 1 inherited assertion, 8 LFS PATH setup failures; 4 supplemental pass and 1 bounded LFS timeout. |

### Third batch: next declared consumers

| Distribution | Release | U | S | F | K | Selected coverage and limits |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| duplocloud-client | 0.4.5 | 0 | 12 | 0 | 0 | 12 real build/version helper checks; no upstream Git tests; whole unchanged module. |
| phidata | 2.7.10 | 0 | 17 | 0 | 0 | 17 real origin/workspace clone/progress checks; no upstream Git tests; final cloud setup boundary replaced. |
| salt | 3008.3 | 34 | 0 | 0 | 0 | 34 unchanged real GitFS/fileserver/pillar cases; provider detection accepts the source-checkout version; 50 alternative-provider cases deselected. |
| tinybird | 5.0.2 | 0 | 0 | 0 | 0 | Unused declaration: verified source and wheel have no GitPython caller; current Git paths use subprocess. |
| demisto-sdk | 1.39.13 | 25 | 20 | 1 | 0 | 25 upstream cases, five real and 20 mocked/helper; 20 real supplemental passes; root listing also fails with the release. |
| langchain-cli | 0.0.37 | 4 | 8 | 0 | 0 | Four upstream parsing cases and eight real clone/pull/cache supplements of the whole helper module. |
| azdev | 0.2.13 | 0 | 12 | 0 | 0 | 12 real diff/type/patch/module-filter supplements; no upstream Git helper tests; whole unchanged module. |
| apache-airflow-providers-git | 1.0.1 | 175 | 0 | 2 | 0 | 175 upstream cases including 45 real bundle cases; four support fixtures isolated; two mirror-fetch failures also released. |
| codeflash | 0.20.6 | 18 | 20 | 0 | 0 | 18 upstream cases mostly mocked; 20 real branch/remote/diff/config/snapshot/worktree supplements; optimizer/API workflows omitted. |
| nemo-gym | 0.7.0 | 0 | 0 | 0 | 0 | Unused transitive security pin; 2,533 Python files have no GitPython caller; zero tests. |
| h2ogpte | 1.7.5 | 0 | 14 | 0 | 0 | 14 real directory status/history checks; wheel-only source/test availability limit; normal whole module. |
| terraform-compliance | 1.16.0 | 1 | 8 | 0 | 0 | One upstream parser and eight real clone/branch/tag/subdir/depth plus Radish BDD supplements; local URL rewrites. |
| colbert-ai | 0.2.22 | 0 | 16 | 0 | 0 | 16 real metadata supplements; four unchanged helper ASTs and dotdict isolated from Torch; model/training suites omitted. |
| teradatamodelops | 7.3.6 | 4 | 9 | 0 | 0 | Four upstream template mocks and nine real clone/checkout supplements; verified sdist, GitHub source unavailable; no cloud/DB calls. |
| cycode | 3.26.0 | 96 | 6 | 0 | 0 | 96 upstream index/range/document cases including mocks; six real tree/blob and historical/live SCA supplements; no scan API. |
| pkscreener | 0.46.20260615.927 | 0 | 0 | 0 | 0 | Unused declaration; verified sdist and wheel have no GitPython caller; zero runtime tests; scientific stack omitted. |
| mkdocs-git-revision-date-plugin | 0.3.2 | 0 | 9 | 0 | 0 | Nine real dated-history/page-hook supplements; no upstream tests; Git.log CLI fallback; initial harness mistakes corrected. |
| flux-local | 8.4.0 | 31 | 11 | 0 | 0 | 31 upstream cases and 19 snapshots; 11 real fetch/refresh/worktree supplements; verified Flux/Kustomize tools. |
| dirac | 9.1.21 | 0 | 12 | 0 | 0 | 12 real synchronization, fetch/pull/checkout/archive and release-helper supplements; normal full modules; no upstream Git tests. |
| cognee | 1.6.5 | 0 | 0 | 0 | 0 | Unused development declaration; 2,802 Python files have no GitPython imports; Git tests use subprocesses; zero tests. |
| neptune | 1.14.0.post2 | 19 | 15 | 0 | 0 | 19 upstream metadata cases including mocks; 15 real modern/legacy metadata, tracking, diff and detached-head supplements; no live API. |
| unidep | 3.4.2 | 5 | 10 | 0 | 0 | Five upstream parser cases and ten actual pytest --run-affected Git plugin supplements; staged/untracked omissions preserved. |
| mace-torch | 0.3.16 | 0 | 7 | 0 | 0 | Seven real commit-report supplements; exact unchanged helper AST isolated from Torch/e3nn; no upstream Git tests. |
| neptune-scale | 0.30.0 | 0 | 13 | 0 | 0 | 13 real metadata/dirty/tracking/merge-base/diff supplements; normal SDK module; live upload tests excluded. |
| opentimestamps-client | 0.7.2 | 1 | 11 | 0 | 0 | One upstream hash-only test and 11 real offline extraction/tree/blob supplements; synthetic signature/pending proof; no calendar/GnuPG validation. |
| robot-descriptions | 3.3.0 | 11 | 11 | 0 | 0 | 11 byte-identical upstream clone/progress cases and 11 real cache/tag/SHA/shallow supplements; local fixtures avoid assets; test initializer isolated. |
| wily | 1.25.0 | 117 | 0 | 0 | 0 | 117 unchanged integration/archiver tests, two with Repo mocks; all pass with the release; branch/quota setup failures retained. |
| kas | 5.5 | 0 | 11 | 3 | 0 | 11 real diff/shallow/identity supplements pass; three upstream SSH empty-section compatibility failures retained. |
| exasol-integration-test-docker-environment | 6.5.1 | 0 | 7 | 0 | 0 | Seven real get_commit_id supplements; normal module without Docker constructor; no upstream Git tests or Docker workflow. |
| comfy-cli | 1.23.0 | 20 | 19 | 0 | 0 | 20 upstream cases and 19 real repository/workspace installation checks; other Git helpers use subprocesses; no server/model actions. |
| airbyte-internal-ops | 0.126.5 | 0 | 20 | 2 | 0 | 20 real supplements pass; two nested third-party path failures also released; whole utilities module and three AST helpers; cloud stack omitted. |
| nipype | 1.12.0 | 0 | 7 | 0 | 0 | Seven real full Zenodo maintainer-script supplements; no upstream Git caller tests; neuroimaging stack omitted. |
| sam3 | 0.1.4 | 0 | 0 | 0 | 0 | Unused development pin; 140 Python files have no direct/dynamic Git imports; zero tests; model/Torch stack omitted. |
| mkdocs-rss-plugin | 1.19.0 | 5 | 10 | 0 | 0 | Five unchanged date/no-repo builds and ten real history/meta/shallow/CiHandler supplements; Optional import supported; normal modules. |
| pytextrank | 3.3.0 | 0 | 16 | 0 | 0 | 16 real version/commit/tag supplements; complete version module imported by file; spaCy omitted; no upstream Git tests. |
| apm-cli | 0.34.0 | 184 | 10 | 0 | 0 | 184 unchanged metadata/cache/contract cases and ten real clone/progress/detached/worktree/locked-HEAD supplements; no MCP/API services. |
| hf-doc-builder | 0.5.0 | 0 | 16 | 0 | 0 | 16 real ls_remote/tag and local HTTP inventory supplements; normal external module; CLI-only Git caller; no upstream Git tests. |
| pretext | 2.56.0 | 1 | 8 | 0 | 0 | One upstream URL parser and eight real no_push helper checks with local gh-pages commits; normal modules/private resources; no external publish. |
| copychat | 0.7.2 | 3 | 13 | 0 | 0 | Three unchanged upstream cases and 13 real clone/cache/fetch/pull/dirty/error supplements; fixed URL rewritten locally; normal module. |

### Fourth batch: remaining snapshot consumers

| Distribution | Release | U | S | F | K | Selected coverage and limits |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| compliance-trestle | 5.2.0 | 0 | 13 | 0 | 0 | 13 real unchanged release-tag development-script checks; no upstream Git tests; published runtime has no GitPython caller. |
| mongo-tooling-metrics | 1.0.8 | 0 | 16 | 0 | 0 | 16 real GitInfo metadata/error supplements; normal whole module and pinned dependencies on Python 3.11; no upstream tests/source repository. |
| dstack | 0.22.5 | 24 | 16 | 1 | 0 | 24 upstream mocked URL/template cases; 16 real metadata/clone/diff/ancestry supplements pass; nested default-branch truncation also fails with the release. |
| nvidia-physicsnemo | 2.2.2 | 0 | 8 | 0 | 0 | Eight real metadata supplements; entire unchanged version-check module imported by file; no upstream Git helper tests; Torch/warp omitted. |
| dvsim | 1.56.1 | 15 | 15 | 0 | 0 | 15 unchanged upstream plus 15 real supplements; complete Repo_helper and lint_commits script; workspace environment migration disclosed. |
| promptflow-devkit | 1.18.5 | 0 | 11 | 0 | 0 | 11 real checks of required promptflow-core 1.18.5 helper; exact wheels verified; full Run SDK only inspected; no exact-release upstream tests. |
| sdv | 2.0.0 | 0 | 14 | 0 | 0 | 14 real test/benchmark metadata supplements; whole gdrive helper module; exact benchmark-helper AST avoids ML imports; no upstream Git helper tests. |
| mknotebooks | 0.8.0 | 0 | 9 | 0 | 0 | Nine real full-plugin/notebook supplements and one separate unchanged Binder MkDocs build; all pass released baseline; harness import/scratch corrections disclosed. |
| kubernetes-typed | 18.20.2 | 1 | 7 | 0 | 0 | One unchanged full stub-generation upstream test plus seven real generator supplements; real client/submodule clones; tag setup advanced to 18.20.3-dev; quota attempt retained. |
| codechecker | 6.29.1 | 0 | 13 | 0 | 0 | 13 real blame/range/metadata/process-pool ZIP supplements; normal prepared library module; upstream functional server/compiler suite unrun. |
| cellxgene-census | 1.18.0 | 0 | 8 | 0 | 0 | Eight real whole docs/conf.py version/tag supplements; doc extra uses GitPython; released runtime has no callers; no data/scientific stack. |
| worker-automate-hub | 0.5.1174 | 0 | 12 | 0 | 0 | 12 real normal-module clone/fetch/pull/reclone supplements; no shipped upstream tests; Linux literal-backslash paths preserve Windows-oriented caller behavior. |
| yolov5 | 7.0.14 | 0 | 18 | 0 | 0 | 18 real metadata/error supplements; exact Git helper/decorator and original Ultralytics checker AST chain; absent Torchvision is caught by original checker; no model imports. |
| python-kacl | 0.7.7 | 77 | 9 | 0 | 2 | 77 unchanged upstream passes/two live Jira skips plus nine real Git caller supplements; full modules and release CLI; corrected harness also passes released baseline. |
| qubx | 4.3.1 | 0 | 18 | 0 | 0 | 18 real release/stage/commit/tag/config/local-push supplements; exact unchanged AST helpers avoid missing compiled trading module; upstream mock suites unrun. |

## Reproduction and evidence

The [five-profile CI runner](README.md) maintains LangChain, MLflow, Bandit, SWE-bench
and DataHub. It is not an automated replay of all 115 projects. For example:

```sh
uv run test/downstream/run.py bandit --version 1.9.4 --backend cli
uv run test/downstream/run.py bandit --version 1.9.4 --backend gix
```

Select the backend before imports and reverify the editable import after dependency
installation. Additional selections require the disclosed project-specific harness.
Original sources, environments, commands, logs, JUnit XML and helper scripts were kept
under ignored `.cache/downstream-audit/`, `.cache/downstream-audit-2/`,
`.cache/downstream-audit-3/`, `.cache/downstream-audit-4/` and per-project temporary directories.
These local artifacts may not exist in another checkout.

This file replaces the four batch reports and JSON manifests. Detailed historical
provenance, commands and baseline evidence remain in Git at **`46303c88`**, e.g.
`git show 46303c88:test/downstream/audit-2026-10-22-batch-3.json`.
Fresh reproduction requires recreating the harness; the compact report alone does
not contain downloaded third-party sources, frozen environments or all supplemental runners.
