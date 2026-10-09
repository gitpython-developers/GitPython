"""The benchmark comparison must reject incompatible workloads and results."""

import json

import pytest

pyperf = pytest.importorskip("pyperf")


@pytest.mark.parametrize("changed", [None, "result_digest", "fixture_revision", "backend", "cli_processes"])
def test_comparison_requires_parity(tmp_path, capsys, changed):
    from test.performance.compare_backends import compare

    metadata = {
        "gitpython_revision": "source",
        "fixture_revision": "fixture",
        "fixture_tree": "tree",
        "fixture_status": "clean",
        "fixture_object_format": "sha1",
        "fixture_ref_format": "files",
        "git_version": "git version 2.52.0",
        "python_version": "3.12.14",
        "result_digest": "equal",
        "backend_decisions": "[]",
        "cli_processes": 0,
        "name": "journey",
    }
    paths = [tmp_path / "cli.json", tmp_path / "gix.json"]
    for backend, path in zip(("cli", "gix"), paths):
        values = {**metadata, "backend": backend}
        if backend == "gix" and changed:
            values[changed] = 1 if changed == "cli_processes" else "different"
        run = pyperf.Run([0.1, 0.2], metadata=values, collect_metadata=False)
        pyperf.BenchmarkSuite([pyperf.Benchmark([run])]).dump(str(path))
    budget = tmp_path / "budget.json"
    budget.write_text(json.dumps({"fixture_revision": "fixture", "max_gix_cli_processes": {"journey": 0}}))
    if changed:
        with pytest.raises(ValueError, match="differ|Expected|exceed"):
            compare(*paths, cli_budget=budget)
    else:
        compare(*paths, cli_budget=budget)
        assert "journey | 150.00" in capsys.readouterr().out
        budget.write_text(json.dumps({"fixture_revision": "fixture", "max_gix_cli_processes": {"journey": 1}}))
        compare(*paths, cli_budget=budget)  # A reduction stays within the ceiling.
