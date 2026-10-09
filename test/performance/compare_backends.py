"""Validate benchmark parity and print every measurement, including slowdowns."""

import argparse
import json
from pathlib import Path

import pyperf


def compare(cli_path, gix_path, cli_budget=None):
    cli, gix = pyperf.BenchmarkSuite.load(str(cli_path)), pyperf.BenchmarkSuite.load(str(gix_path))
    budget = json.loads(Path(cli_budget).read_text()) if cli_budget else None
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
        if budget is not None:
            if rm["fixture_revision"] != budget["fixture_revision"]:
                raise ValueError("CLI process budget belongs to a different fixture")
            limit = budget["max_gix_cli_processes"][name]
            if rm["cli_processes"] > limit:
                raise ValueError(f"{name}: {rm['cli_processes']} CLI launches exceed ceiling {limit}")
        native = sum(item["count"] for item in decisions if item["outcome"] == "native")
        fallback = sum(item["count"] for item in decisions if item["outcome"].startswith("CLI:"))
        rows.append(
            f"| {name} | {left.mean() * 1000:.2f} ± {left.stdev() * 1000:.2f} "
            f"| {right.mean() * 1000:.2f} ± {right.stdev() * 1000:.2f} "
            f"| {left.mean() / right.mean():.2f}× | {native} / {fallback} "
            f"| {lm['cli_processes']} / {rm['cli_processes']} |"
        )
    print(
        "| Measurement | CLI mean ± stdev (ms) | GixPython mean ± stdev (ms) "
        "| CLI / Gix | Native / fallback | CLI launches: CLI / Gix |"
    )
    print("| --- | ---: | ---: | ---: | ---: | ---: |")
    print("\n".join(rows))
    print("\nRatios above 1 favor GixPython. Decisions are per invocation; CLI launches count Git.execute processes.")
    print("\nWarm-cache, read-only measurements; checkout, imports and preflight are outside timing.")
    print("The journey reuses one open Repo; opening and nested discovery are measured separately.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli_path")
    parser.add_argument("gix_path")
    parser.add_argument("--cli-budget", help="JSON ceilings for GixPython's launches on the fixed fixture")
    compare(**vars(parser.parse_args()))
