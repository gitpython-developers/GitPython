"""Report native coverage when the optional backend is installed."""

from collections import Counter
import json
from pathlib import Path

import pytest

from git import Repo, _backend
from test.lib import GIT_REPO, TestBase


def pytest_addoption(parser):
    parser.addoption("--backend-report", help="Write native/CLI operation counts as JSON")
    parser.addoption("--max-cli-processes", type=int, help="Maximum Git.execute launches in the pytest session")
    parser.addoption("--max-cli-test-processes", type=int, help="Maximum Git.execute launches in test call phases")


def cli_processes():
    return _backend.statistics().get(("Git.execute", "CLI process"), 0)


def pytest_configure(config):
    for option in ("--max-cli-processes", "--max-cli-test-processes"):
        limit = config.getoption(option)
        if limit is not None and limit < 0:
            raise pytest.UsageError(option + " must be nonnegative")
    config._cli_process_start = cli_processes()
    config._cli_process_phases = Counter()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_setup(item):
    before = cli_processes()
    yield
    item.config._cli_process_phases["setup"] += cli_processes() - before


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    before = cli_processes()
    yield
    item.config._cli_process_phases["call"] += cli_processes() - before


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_teardown(item):
    before = cli_processes()
    yield
    item.config._cli_process_phases["teardown"] += cli_processes() - before


def pytest_sessionfinish(session, exitstatus):
    config = session.config
    actual = {
        "--max-cli-processes": cli_processes() - config._cli_process_start,
        "--max-cli-test-processes": config._cli_process_phases["call"],
    }
    config._cli_process_failures = [
        f"{option}: {count} launches exceed ceiling {config.getoption(option)}"
        for option, count in actual.items()
        if config.getoption(option) is not None and count > config.getoption(option)
    ]
    if config._cli_process_failures:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_report_header(config):
    return "GitPython backend: " + _backend.name


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    total = cli_processes() - config._cli_process_start
    phases = config._cli_process_phases
    terminalreporter.section("Git CLI process launches")
    terminalreporter.write_line(
        f"{total} total: {phases['setup']} setup, {phases['call']} call, "
        f"{phases['teardown']} teardown, {total - sum(phases.values())} collection/session"
    )
    for failure in config._cli_process_failures:
        terminalreporter.write_line(failure, red=True)
    records = [
        {"method": method, "outcome": outcome, "count": count}
        for (method, outcome), count in sorted(_backend.statistics().items())
    ]
    if _backend.name == "gix":
        terminalreporter.section("GixPython operation coverage")
        for item in records:
            terminalreporter.write_line("{method}: {outcome} ({count})".format(**item))
    records.extend(
        {"method": "pytest." + phase, "outcome": "CLI process", "count": count}
        for phase, count in sorted({**phases, "session_total": total}.items())
    )
    path = config.getoption("--backend-report")
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(records, stream, indent=2)
            stream.write("\n")


@pytest.fixture(scope="session")
def dependency_repo_factory(tmp_path_factory):
    """Prepare each immutable historical clone source only when a test needs it."""
    root = tmp_path_factory.mktemp("dependency-repos")
    paths = {}

    def get(name):
        if name not in paths:
            revision = {
                "gitdb": "2da3232f9d58e7761e384ac6d32f7b1ed77a74a2",
                "smmap": "8ce61ad5cc4016bffaf25080bc0d69b3acbe8555",
            }[name]
            path = root / name
            with Repo(GIT_REPO) as source, source.clone(path, shared=True, no_checkout=True) as repo:
                repo.create_head("master", repo.commit(revision), force=True).checkout()
                if name == "smmap":
                    repo.create_tag("v0.8.1", ref="master~10", message="Test fixture tag", force=True)
                repo.git.gc()
            paths[name] = str(path)
        return paths[name]

    return get


@pytest.fixture(scope="class", autouse=True)
def historical_dependency_sources(request):
    if request.cls is not None and issubclass(request.cls, TestBase):
        factory = request.getfixturevalue("dependency_repo_factory")
        request.cls._dependency_repo_factory = staticmethod(factory)
        yield
        del request.cls._dependency_repo_factory
    else:
        yield
