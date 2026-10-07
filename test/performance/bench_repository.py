"""Read-only GitPython journeys, measured with pyperf against an existing checkout.

Run as a module from the source root so pyperf workers import this checkout:
    python -m test.performance.bench_repository --repo /path/to/repo --expect-backend gix -o gix.json
"""

from hashlib import sha256
from importlib.metadata import version
import json
import os
from pathlib import Path
import subprocess

import pyperf

from git import Repo, _backend


def inventory(repo):
    return {
        "head": repo.head.commit.hexsha if repo.head.is_detached else repo.head.reference.path,
        "refs": sorted(ref.path for ref in repo.references),
    }


def history(repo):
    return [
        [commit.hexsha, str(commit.author), commit.authored_date, commit.message]
        for commit in repo.iter_commits("HEAD", max_count=25, first_parent=True)
    ]


def browse(repo):
    tree = repo.commit("HEAD").tree
    blob = tree / "README.md"
    content = blob.data_stream.read()
    return {
        "entries": [[entry.path, entry.mode, entry.hexsha] for entry in tree],
        "readme": sha256(content).hexdigest(),
    }


def index(repo):
    return sorted([path, stage, entry.mode, entry.hexsha] for (path, stage), entry in repo.index.entries.items())


def graph(repo):
    tip, parent = repo.commit("HEAD"), repo.commit("HEAD~1")
    return {
        "count": tip.count(),
        "merge_base": [commit.hexsha for commit in repo.merge_base(parent, tip)],
        "is_ancestor": repo.is_ancestor(parent, tip),
    }


def changes(repo):
    tip = repo.commit("HEAD")
    return {
        "diff": [[diff.change_type, diff.a_path, diff.b_path] for diff in tip.parents[0].diff(tip)],
        "stats": tip.stats.total,
    }


def patch(repo):
    tip = repo.commit("HEAD")
    return [sha256(diff.diff).hexdigest() for diff in tip.parents[0].diff(tip, create_patch=True)]


def worktree(repo):
    return {
        "dirty": repo.is_dirty(untracked_files=True),
        "untracked": sorted(repo.untracked_files),
        "ignored": repo.ignored(".benchmark-cache/probe"),
    }


# Add a named public-API operation here: it is measured separately and joins the
# complete journey automatically. Return JSON-compatible data for parity checks.
MEASUREMENTS = {
    "inventory": inventory,
    "history_25": history,
    "browse_tree_and_blob": browse,
    "read_index": index,
    "revision_graph": graph,
    "diff_and_stats": changes,
    "patch_diff": patch,
    "worktree_status": worktree,
}


def journey(repo):
    return {name: operation(repo) for name, operation in MEASUREMENTS.items()}


def open_repository(path):
    with Repo(path) as opened:
        return [opened.bare, opened.object_format, opened.ref_format]


def discover_repository(path):
    with Repo(path, search_parent_directories=True) as opened:
        return [opened.bare, opened.object_format, opened.ref_format]


def worker_arguments(cmd, args):
    cmd.extend(["--repo", str(args.repo), "--expect-backend", args.expect_backend])


def main():
    runner = pyperf.Runner(
        processes=6,
        values=3,
        program_args=("-m", "test.performance.bench_repository"),
        add_cmdline_args=worker_arguments,
    )
    runner.argparser.add_argument("--repo", type=Path, required=True, help="Existing worktree; never modified")
    runner.argparser.add_argument("--expect-backend", choices=("cli", "gix"), required=True)
    args = runner.parse_args()
    args.repo = args.repo.resolve()
    if _backend.name != args.expect_backend:
        raise RuntimeError(f"Expected {args.expect_backend}, imported {_backend.name}; use separate installations")
    # The manager and every worker use the same isolated Git environment.
    for key in list(os.environ):
        if key.startswith("GIT_"):
            del os.environ[key]
    os.environ.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0")

    def git(*arguments, cwd=args.repo):
        return subprocess.check_output(["git", *arguments], cwd=cwd, text=True).strip()

    runner.metadata.update(
        backend=_backend.name,
        gixpython=version("GixPython") if _backend.name == "gix" else "absent",
        git_version=git("version"),
        gitpython_revision=git("rev-parse", "HEAD", cwd=Path.cwd()),
        fixture_revision=git("rev-parse", "HEAD"),
        fixture_tree=git("rev-parse", "HEAD^{tree}"),
        fixture_status=git("status", "--porcelain") or "clean",
        fixture_object_format=git("rev-parse", "--show-object-format"),
        fixture_ref_format=git("rev-parse", "--show-ref-format"),
    )
    with Repo(args.repo) as repo:
        measurements = [("journey", journey, repo)]
        measurements.extend((name, operation, repo) for name, operation in MEASUREMENTS.items())
        measurements.extend(
            [
                ("open_repository", open_repository, args.repo),
                ("discover_repository", discover_repository, args.repo / "git" / "objects"),
            ]
        )
        for name, operation, target in measurements:
            operation(target)  # Warm persistent CLI processes before counting.
            # Untimed preflight validates parity and records native/fallback
            # decisions for ONE invocation, rather than calibrated loop counts.
            before = _backend.statistics()
            result = operation(target)
            decisions = [
                {"method": method, "outcome": outcome, "count": count - before.get((method, outcome), 0)}
                for (method, outcome), count in sorted(_backend.statistics().items())
                if count > before.get((method, outcome), 0)
            ]
            metadata = {
                "result_digest": sha256(json.dumps(result, sort_keys=True).encode()).hexdigest(),
                "backend_decisions": json.dumps(decisions, sort_keys=True),
                "cli_processes": sum(
                    item["count"]
                    for item in decisions
                    if (item["method"], item["outcome"]) == ("Git.execute", "CLI process")
                ),
            }
            runner.bench_func(name, operation, target, metadata=metadata)


if __name__ == "__main__":
    main()
