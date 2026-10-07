"""Validate benchmark parity and print every measurement, including slowdowns."""

import json
import sys

import pyperf


def compare(cli_path, gix_path):
    cli, gix = pyperf.BenchmarkSuite.load(str(cli_path)), pyperf.BenchmarkSuite.load(str(gix_path))
    if cli.get_benchmark_names() != gix.get_benchmark_names():
        raise ValueError("The backends measured different journeys")
    rows = []
    for name in cli.get_benchmark_names():
        left, right = cli.get_benchmark(name), gix.get_benchmark(name)
        lm, rm = left.get_metadata(), right.get_metadata()
        if (lm["backend"], rm["backend"]) != ("cli", "gix"):
            raise ValueError("Expected CLI results followed by GixPython results")
        for key in (
            "gitpython_revision",
            "fixture_revision",
            "fixture_tree",
            "fixture_status",
            "fixture_object_format",
            "fixture_ref_format",
            "git_version",
            "python_version",
            "result_digest",
        ):
            if lm[key] != rm[key]:
                raise ValueError(f"{name}: backends differ in {key}: {lm[key]!r} != {rm[key]!r}")
        decisions = json.loads(rm["backend_decisions"])
        native = sum(item["count"] for item in decisions if item["outcome"] == "native")
        fallback = sum(item["count"] for item in decisions if item["outcome"].startswith("CLI:"))
        rows.append(
            f"| {name} | {left.mean() * 1000:.2f} ± {left.stdev() * 1000:.2f} "
            f"| {right.mean() * 1000:.2f} ± {right.stdev() * 1000:.2f} "
            f"| {left.mean() / right.mean():.2f}× | {native} / {fallback} |"
        )
    print("| Measurement | CLI mean ± stdev (ms) | GixPython mean ± stdev (ms) | CLI / Gix | Native / fallback |")
    print("| --- | ---: | ---: | ---: | ---: |")
    print("\n".join(rows))
    print("\nRatios above 1 favor GixPython. Decisions are per invocation, not subprocess counts.")
    print("\nWarm-cache, read-only measurements; checkout, imports and preflight are outside timing.")
    print("The journey reuses one open Repo; opening and nested discovery are measured separately.")


if __name__ == "__main__":
    compare(*sys.argv[1:])
