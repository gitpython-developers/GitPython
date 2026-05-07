# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Verify that fixture directories are usable by git.

If a directory the test suite relies on is rejected by git for "dubious
ownership" -- because the directory's owner doesn't match the running user
and there is no ``safe.directory`` entry overriding the check -- three
submodule-related tests fail in confusing ways. The checks here name the
root cause clearly so a misconfigured environment is recognizable from the
test output.

The rejection is most often a CI-workflow problem (the workflow's
``safe.directory`` list doesn't cover the path); on a developer's own
clone, it usually reflects an ownership mismatch (sudo clone, restored
backup, container mount, networked filesystem) rather than a config gap.

These tests do not exercise GitPython's production code. They verify the
conditions under which production code is exercised are valid.

A check is skipped, rather than failed, if a fixture directory is missing or
has no ``.git`` marker, since that condition is more naturally diagnosed as
"``init-tests-after-clone.sh`` hasn't been run" than as a problem with
``safe.directory``.
"""

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Directories git must trust for the test suite to operate normally. The
# current set is the GitPython working tree plus the working trees of its
# gitdb submodule and the smmap submodule nested inside gitdb. New entries
# should be added here whenever the test suite gains a dependency on git
# accepting another directory.
FIXTURE_DIRS = [
    pytest.param(REPO_ROOT, id="repo_root"),
    pytest.param(REPO_ROOT / "git" / "ext" / "gitdb", id="gitdb"),
    pytest.param(
        REPO_ROOT / "git" / "ext" / "gitdb" / "gitdb" / "ext" / "smmap",
        id="smmap",
    ),
]


@pytest.mark.parametrize("fixture_dir", FIXTURE_DIRS)
def test_fixture_dir_is_trusted_by_git(fixture_dir: Path) -> None:
    """git accepts ``fixture_dir`` as its own repository owned by a trusted user.

    Run ``git -C <fixture_dir> rev-parse --show-toplevel`` and assert it
    succeeds and reports ``fixture_dir`` itself as the toplevel. Failure
    typically means the directory's on-disk ownership doesn't match the
    running user and the CI workflow's ``safe.directory`` list is missing
    an entry that would override the check.
    """
    if not fixture_dir.exists():
        pytest.skip(f"{fixture_dir} not present (run `git submodule update --init --recursive` from the repo root)")
    if not (fixture_dir / ".git").exists():
        pytest.skip(
            f"{fixture_dir} has no .git marker "
            "(submodule not initialized; run "
            "`git submodule update --init --recursive` from the repo root)"
        )
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
