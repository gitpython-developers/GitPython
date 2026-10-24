"""The benchmark comparison must reject incompatible workloads and results."""

import pytest

from test.lib.fixtures import read_only_fixture

pytest.importorskip("pyperf")


@pytest.mark.parametrize("changed", [None, "result_digest", "fixture_revision", "backend", "cli_processes"])
def test_comparison_requires_parity(capsys, changed):
    from test.performance.compare_backends import compare

    fixture = read_only_fixture("benchmark-comparison.sh", changed or "equal")
    paths = [fixture / "cli.json", fixture / "gix.json"]
    if changed:
        with pytest.raises(ValueError, match="differ|Expected|exceed"):
            compare(*paths, cli_budget=fixture / "budget.json")
    else:
        compare(*paths, cli_budget=fixture / "budget.json")
        assert "journey | 150.00" in capsys.readouterr().out
        compare(*paths, cli_budget=fixture / "relaxed-budget.json")
