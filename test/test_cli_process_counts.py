"""Count actual launches, including failures after spawn and persistent processes."""

import subprocess
from types import SimpleNamespace

import pytest

from git import Git, _backend
from git.exc import GitCommandError, GitCommandNotFound


def process_count():
    return _backend.statistics().get(("Git.execute", "CLI process"), 0)


def test_process_count_tracks_success_failure_and_persistent_process(tmp_path):
    git = Git(tmp_path)
    before = process_count()
    git.version()
    assert process_count() == before + 1
    with pytest.raises(GitCommandError):
        git.rev_parse("--verify", "HEAD")
    assert process_count() == before + 2
    process = git.version(as_process=True)
    process.proc.communicate()
    process.wait()
    assert process_count() == before + 3


def test_process_count_ignores_missing_executable_and_external_launch(tmp_path):
    before = process_count()
    with pytest.raises(GitCommandNotFound):
        Git(tmp_path).execute([str(tmp_path / "missing-git")])
    assert process_count() == before
    subprocess.run([Git.GIT_PYTHON_GIT_EXECUTABLE, "version"], check=True, capture_output=True)
    assert process_count() == before


@pytest.mark.parametrize("limit,failed", [(3, False), (4, False), (2, True)])
@pytest.mark.parametrize("option", ["--max-cli-processes", "--max-cli-test-processes"])
def test_pytest_cli_ceiling_sets_exit_status(monkeypatch, option, limit, failed):
    from test import conftest

    config = SimpleNamespace(
        getoption=lambda name: limit if name == option else None,
        _cli_process_start=2,
        _cli_process_phases={"call": 3},
    )
    session = SimpleNamespace(config=config, exitstatus=pytest.ExitCode.OK)
    with monkeypatch.context() as patch:
        patch.setattr(conftest, "cli_processes", lambda: 5)
        conftest.pytest_sessionfinish(session, pytest.ExitCode.OK)
    assert bool(config._cli_process_failures) is failed
    assert session.exitstatus == (pytest.ExitCode.TESTS_FAILED if failed else pytest.ExitCode.OK)
