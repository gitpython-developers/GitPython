# Downstream compatibility

Run released projects' GitPython-related tests against this checkout with
[uv](https://docs.astral.sh/uv/) and Git 2.52 or newer:

```sh
uv run test/downstream/run.py bandit
uv run test/downstream/run.py bandit --version 1.9.4
```

The default resolves the latest release from PyPI each time. `--version` reproduces
a release; `--python` selects the test interpreter (default: 3.12). The runner
creates a fresh environment, replaces GitPython with this editable checkout, and checks
the imported module before testing. Upstream test files are not modified.

Source, the environment, frozen requirements, JUnit results, and release provenance
are retained under `.cache/downstream/`. `--work-dir PATH` uses a new directory
elsewhere. Delete retained directories when no longer needed. PyPI source archives
are verified against their published SHA-256 digest and extracted with Python's
safe data filter. Each run uses a private Git configuration, including an identity
and the `master` initial branch expected by upstream fixtures. Inherited Git
settings and Python import paths are cleared before setup and testing. Select a
different Git executable by putting its directory first on `PATH`.

## Selection and coverage

The selection uses current runtime users, including optional end-user features,
ranked by September 2026 PyPI distribution downloads. Development, documentation,
and test-only dependencies are excluded. Downloads are not unique installations.

| Project | Distribution downloads | Last tested release | Selected coverage |
| --- | ---: | --- | --- |
| LangChain Community | 27,882,881 | 0.4.2 | 2 upstream GitLoader tests: real clones, commits, checkout, tree traversal, ignored paths, and remote validation |
| MLflow (`mlflow-skinny`) | 25,850,354 | 3.16.1 | 47 upstream tests: 31 repository/project/model-versioning cases plus 16 Git context and credential-redaction contract cases |
| Bandit | 24,935,372 | 1.9.4 | 12 upstream baseline CLI tests: real repository creation, commits, branches, resets, discovery, and dirty state |
| SWE-bench | 22,942,741 | 5.0.2 | 4 supplemental integration cases for `AutoContextManager`; no upstream tests cover its GitPython callers |

Source: [top-pypi-packages](https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json),
snapshot updated **2026-10-01 12:40:51 UTC**. Its
[ClickHouse query](https://github.com/hugovk/top-pypi-packages/blob/main/top-pypi-clickhouse.py)
covers the previous calendar month. Current metadata for the top 5,000
distributions was checked, together with known runtime integrations.

LangChain Community's published `GitLoader` integration uses GitPython at runtime
and asks users to install it manually. It qualifies as a current user even though
GitPython is absent from its package dependency metadata. Its upstream
`--only-extended` option ensures missing integration dependencies fail collection
instead of silently skipping the GitLoader tests. These tests use local fixtures.

Bandit's GitPython dependency belongs to its user-facing `baseline` extra.
Two selected tests mock error paths; the others use real repositories.

MLflow is counted once, using its largest consuming distribution,
`mlflow-skinny`, without adding overlapping distribution counts. The tests install
the matching full `mlflow` release because upstream global fixtures import its
server and SQLite tracking support. Selected cases cover branches, fetches,
checkout, invalid versions, Git context, remote URLs, Python subprocesses, dirty
repositories, and staged/unstaged model-versioning diffs.
Some tests clone the public `mlflow/mlflow-example` repository or start a localhost
HTTP server. `CI` and `GITHUB_ACTIONS` are unset only for downstream setup/tests:
upstream autouse fixtures otherwise build wheels and modify conda environments.
No model downloads, cloud credentials, or external tracking server are needed.
CLI examples that train models or need private SSH credentials are excluded.

SWE-bench 5.0.2 ships no upstream tests for its GitPython inference helpers and
has no corresponding Git release tag. Its profile installs the verified PyPI
source archive without unrelated ML dependencies, then imports the real upstream
`AutoContextManager` with `chardet` and GitPython. Our explicitly labeled
[supplemental check](checks/swebench.py) exercises local cloning, commit checkout,
reset, untracked-file cleanup, directory restoration, and clone reuse across
SHA-1/SHA-256 and files/reftable. Git URL rewriting routes the ordinary upstream
URL to a local fixture; `GIT_ALLOW_PROTOCOL=file` prevents network access during
the test. No upstream code, imported modules, or GitPython calls are mocked.
The separate BM25 retrieval helpers require Java/Pyserini and are not covered.
The supplemental filename is intentionally excluded from GitPython's normal test
collection; the runner selects it explicitly with importlib mode to avoid
shadowing the upstream `swebench` package.

CI runs the same command against the latest release and fails when no test passes,
including when all selected tests are skipped. Test dependency ranges only supply
the upstream test harness; they do not pin the dependent's release.
