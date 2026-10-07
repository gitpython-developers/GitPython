"""The benchmark comparison must reject incompatible workloads and results."""

import pytest

pyperf = pytest.importorskip("pyperf")


@pytest.mark.parametrize("changed", [None, "result_digest", "fixture_revision", "backend"])
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
        "name": "journey",
    }
    paths = [tmp_path / "cli.json", tmp_path / "gix.json"]
    for backend, path in zip(("cli", "gix"), paths):
        values = {**metadata, "backend": backend}
        if backend == "gix" and changed:
            values[changed] = "different"
        run = pyperf.Run([0.1, 0.2], metadata=values, collect_metadata=False)
        pyperf.BenchmarkSuite([pyperf.Benchmark([run])]).dump(str(path))
    if changed:
        with pytest.raises(ValueError, match="differ|Expected"):
            compare(*paths)
    else:
        compare(*paths)
        assert "journey | 150.00" in capsys.readouterr().out
