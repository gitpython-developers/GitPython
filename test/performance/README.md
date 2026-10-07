# Backend benchmark

`bench_repository.py` uses `pyperf` to measure a complete read-only journey and
eight named operations against an existing repository, plus separate direct
opening and nested-directory discovery measurements. It keeps one `Repo`
instance open per worker, but creates fresh commit/tree/index wrappers per
invocation so their cached properties cannot turn the measurement into a no-op.
The CLI's persistent `cat-file` processes and the filesystem cache are warmed.
Repository creation, imports, preflight and result hashing are outside timing.
Native handle refresh and compatibility checks remain inside timing, exposing
the benefit of retaining a Gix repository across operations. Opening and
discovery retain explicit CLI fallbacks tracked in `cli-budget.json`.
`open_repository` and `discover_repository` instead create and close a new
`Repo` in each timed invocation; they do not join the already-open journey.

Use two installations with **the same existing CPython interpreter**, one with
`.[gix]` and one without GixPython. Install the benchmark-only dependency in
both environments:

```sh
uv pip install --python .tox/gix/bin/python -r test/performance/benchmark-requirements.txt
uv pip install --python .venv/bin/python -r test/performance/benchmark-requirements.txt
```

Prepare the same fixed repository used by CI (GitPython 3.1.45), outside the
source checkout and outside the measured code. No remote access is needed if
that revision already exists locally:

```sh
BENCH_REPO=/tmp/gitpython-benchmark-repo
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
git init --object-format=sha1 --ref-format=files "$BENCH_REPO"
git -C "$BENCH_REPO" fetch --no-tags "$PWD" 6ba2c0a2f9ee7feffd7e079621c4845820180c9a
git -C "$BENCH_REPO" checkout -b benchmark FETCH_HEAD
git -C "$BENCH_REPO" config core.excludesFile /dev/null
git -C "$BENCH_REPO" config core.attributesFile /dev/null
git -C "$BENCH_REPO" config core.fsmonitor false
git -C "$BENCH_REPO" config core.untrackedCache false
git -C "$BENCH_REPO" config gc.auto 0
git -C "$BENCH_REPO" config maintenance.auto false
mkdir "$BENCH_REPO/.benchmark-cache"
touch "$BENCH_REPO/.benchmark-cache/probe" "$BENCH_REPO/benchmark-untracked.txt"
echo '.benchmark-cache/' >> "$BENCH_REPO/.git/info/exclude"
```

Run from the source root, sequentially to avoid competing for CPU and disk:

```sh
.tox/gix/bin/python -m test.performance.bench_repository \
    --repo "$BENCH_REPO" --expect-backend gix -o /tmp/gix.json
.venv/bin/python -m test.performance.bench_repository \
    --repo "$BENCH_REPO" --expect-backend cli -o /tmp/cli.json
.tox/gix/bin/python -m test.performance.compare_backends /tmp/cli.json /tmp/gix.json \
    --cli-budget test/performance/cli-budget.json
.tox/gix/bin/python -m pyperf compare_to /tmp/cli.json /tmp/gix.json --table --table-format md
```

The default uses six worker processes, three measured values per process and
one warmup, with calibrated loop counts and a minimum value duration of 100 ms.
Pass standard `pyperf` options such as `--rigorous` for more samples or
`--debug-single-value` for a smoke check. Raw JSON retains sample distributions,
environment details, fixture/source revisions, result digests, and one untimed
invocation's native/fallback decisions. The comparison rejects differing
results, revisions, Python/Git versions and storage formats. The harness also
rejects the wrong backend rather than silently comparing CLI against itself.

The journey inventories refs, reads metadata for 25 first-parent commits,
browses the root tree and README blob, reads index entries, counts reachable
commits and checks ancestry, inspects the latest diff/statistics and patch, and
checks dirty/untracked/ignored paths. An alternative `--repo` must have `HEAD`,
at least one parent, a root `README.md` and a `git/objects` directory for the
nested discovery measurement. The harness never prepares or
mutates that worktree, and ignores ambient Git environment/config overrides.

Add a function returning JSON-compatible results to `MEASUREMENTS` in
`bench_repository.py`. It automatically becomes a separate benchmark and part
of the journey and parity checks. Include supported and fallback operations;
the current patch measurement intentionally exercises fallback. Backend
decisions are adapter events, not complete subprocess counts.

`cli_processes` counts successful launches through `Git.execute` during one
warm invocation, including raw calls and the launch of persistent `cat-file`
processes. Sending another request to an existing process does not increment
it. Native/fallback decisions remain separate: the current warm Gix journey has
two fallback decisions but launches only one process (the patch diff).
Direct subprocesses in the harness and Git's own child processes are excluded.

The checked-in `cli-budget.json` sets maximum Gix launch counts for this pinned
fixture. CI enforces the ceilings: reductions pass, increases fail with the
measurement and counts. Lower ceilings when an optimization lands to retain
the gain. Warm ceilings are journey/patch 1, opening 2, discovery 4,
and zero for the other operations. New measurements need an explicit ceiling;
do not automatically raise an existing ceiling to accept a regression.

The opening/discovery ceilings include a real CLI reference-format query
(`GIX-1`) and version validation. Nested candidates rejected by Gix also use
Git for compatible discovery diagnostics (`GIX-14`). GixPython must expose
the missing capabilities before those calls can disappear; Python inference
does not count as a native implementation.

Timing is observational: shared CI runners and local activity introduce noise.
The CI job publishes all means, standard deviations and ratios, retains raw
artifacts, and uses `pyperf compare_to` for significance reporting. It fails on
execution/parity errors, without a noisy speed threshold. Compare like-for-like
fixture and source revisions when tracking performance across backend changes.
