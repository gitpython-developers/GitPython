"""Report native coverage when the optional backend is installed."""

import json
from pathlib import Path

import pytest

from git import Repo, _backend
from test.lib import GIT_REPO, TestBase


def pytest_addoption(parser):
    parser.addoption("--backend-report", help="Write native/CLI operation counts as JSON")


def pytest_report_header(config):
    return "GitPython backend: " + _backend.name


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if _backend.name != "gix":
        return
    records = [
        {"method": method, "outcome": outcome, "count": count}
        for (method, outcome), count in sorted(_backend.statistics().items())
    ]
    terminalreporter.section("GixPython operation coverage")
    for item in records:
        terminalreporter.write_line("{method}: {outcome} ({count})".format(**item))
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
