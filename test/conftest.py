"""Report native coverage when the optional backend is installed."""

import json
from pathlib import Path

from git import _backend


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
