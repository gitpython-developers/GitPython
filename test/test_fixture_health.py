# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Verify that the source repository is usable by git."""

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

FIXTURE_DIRS = [pytest.param(REPO_ROOT, id="repo_root")]


def test_source_tree_has_no_gitlinks() -> None:
    """All formerly external dependencies are regular monorepo directories."""
    if not (REPO_ROOT / ".git").exists():
        pytest.skip(f"{REPO_ROOT} is not a git checkout")
    try:
        result = subprocess.run(
            ["git", "ls-files", "--stage"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        pytest.skip("git is not installed or not on PATH")
    gitlinks = [line for line in result.stdout.splitlines() if line.startswith("160000 ")]
    assert not gitlinks, "Unexpected submodules:\n" + "\n".join(gitlinks)


@pytest.mark.parametrize("fixture_dir", FIXTURE_DIRS)
def test_fixture_dir_is_trusted_by_git(fixture_dir: Path) -> None:
    """git accepts ``fixture_dir`` as its own repository owned by a trusted user.

    Run ``git -C <fixture_dir> rev-parse --show-toplevel`` and assert it
    succeeds and reports ``fixture_dir`` itself as the toplevel. Failure
    typically means the directory's on-disk ownership doesn't match the
    running user and the CI workflow's ``safe.directory`` list is missing
    an entry that would override the check.
    """
    if not (fixture_dir / ".git").exists():
        pytest.skip(f"{fixture_dir} is not a git checkout")
    try:
        result = subprocess.run(
            ["git", "-C", str(fixture_dir), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        pytest.skip("git is not installed or not on PATH")
    assert result.returncode == 0, (
        f"git refuses to operate in {fixture_dir}.\n"
        f"stderr: {result.stderr.strip()}\n"
        "The directory's owner doesn't match the running user and no "
        "`safe.directory` entry overrides the check. On CI, the "
        "workflow's `safe.directory` list typically needs an entry for "
        "this path. Locally, this is unexpected and usually indicates "
        "an ownership problem worth investigating."
    )
    reported = Path(result.stdout.strip())
    assert reported.samefile(fixture_dir), (
        f"git reports the toplevel as {reported}, "
        f"not as {fixture_dir} itself. "
        "This usually means the directory is not an initialized git "
        "repository (its `.git` marker may be stale or pointing elsewhere)."
    )
