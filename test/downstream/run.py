# /// script
# requires-python = ">=3.12"
# ///
"""Run one released downstream project's GitPython tests in an isolated uv environment."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import quote, urlparse
from urllib.request import urlopen
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent
CHECKOUT = HERE.parent.parent


def run(command, *, cwd=None, env=None, check=True, **kwargs):
    print("+", shlex.join(map(str, command)), flush=True)
    return subprocess.run(command, cwd=cwd, env=env, check=check, **kwargs)


def release_metadata(distribution, version):
    suffix = "" if version is None else "/" + quote(version, safe="")
    url = f"https://pypi.org/pypi/{distribution}{suffix}/json"
    with urlopen(url, timeout=60) as response:
        metadata = json.load(response)
    version = metadata["info"]["version"]
    if not re.fullmatch(r"[0-9][A-Za-z0-9.!+_-]*", version):
        raise ValueError(f"Unexpected release version: {version!r}")
    return metadata, version


def source_tree(profile, metadata, version, work, env):
    source = work / "source"
    if profile["source"] == "git":
        tag = profile["tag"].format(version=version)
        run(
            [
                "git",
                "-c",
                f"core.hooksPath={os.devnull}",
                "clone",
                "--depth=1",
                "--branch",
                tag,
                "--",
                profile["repository"],
                str(source),
            ],
            env=env,
        )
        commit = run(
            ["git", "-C", str(source), "rev-parse", "HEAD"], env=env, capture_output=True, text=True
        ).stdout.strip()
        return source, {"repository": profile["repository"], "tag": tag, "commit": commit}

    sdist = next(item for item in metadata["urls"] if item["packagetype"] == "sdist" and not item["yanked"])
    url = urlparse(sdist["url"])
    if url.scheme != "https" or url.hostname != "files.pythonhosted.org":
        raise ValueError("Expected an HTTPS source archive hosted by PyPI")
    archive = work / "source.tar.gz"
    digest = hashlib.sha256()
    with urlopen(sdist["url"], timeout=60) as response, archive.open("wb") as output:
        while block := response.read(1024 * 1024):
            digest.update(block)
            output.write(block)
    if digest.hexdigest() != sdist["digests"]["sha256"]:
        raise ValueError("Source archive does not match PyPI's SHA-256 digest")
    source.mkdir()
    with tarfile.open(archive) as contents:
        contents.extractall(source, filter="data")
    roots = list(source.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise ValueError("Expected one source directory in the release archive")
    return roots[0], {"url": sdist["url"], "sha256": digest.hexdigest()}


def main():
    profiles = json.loads((HERE / "projects.json").read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", choices=profiles)
    parser.add_argument("--version", help="Release to reproduce; defaults to PyPI's latest release")
    parser.add_argument("--python", default="3.12", help="Python used by the isolated test environment")
    parser.add_argument("--work-dir", type=Path, help="New directory for retained source, environment, and results")
    args = parser.parse_args()
    profile = profiles[args.project]
    metadata, version = release_metadata(profile["distribution"], args.version)
    if args.work_dir:
        work = args.work_dir.resolve()
        work.mkdir(parents=True)
    else:
        cache = CHECKOUT / ".cache" / "downstream"
        cache.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix=f"{args.project}-{version}-", dir=cache))
    print(f"Testing {args.project} {version}; retained work directory: {work}", flush=True)

    config = work / "gitconfig"
    config.write_text(
        "[user]\n\tname = GitPython downstream tests\n\temail = tests@example.invalid\n"
        "[init]\n\tdefaultBranch = master\n[commit]\n\tgpgSign = false\n"
    )
    # Do not let inherited Git settings redirect upstream resets or commits into
    # the caller's repository, index, object database, configuration, or hooks.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env.update(GIT_CONFIG_GLOBAL=str(config), GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
    source, provenance = source_tree(profile, metadata, version, work, env)
    venv = work / "venv"
    run(["uv", "venv", "--python", args.python, str(venv)], env=env)
    bin_dir = venv / ("Scripts" if os.name == "nt" else "bin")
    python = bin_dir / ("python.exe" if os.name == "nt" else "python")
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    env["GITPYTHON_CHECKOUT"] = str(CHECKOUT)
    for key in profile.get("unset_env", []):
        env.pop(key, None)
    env.update(profile.get("env", {}))

    def expand(value):
        return value.format(version=version, source=source, checks=HERE / "checks")

    install = ["uv", "pip", "install", "--python", str(python)]
    run(install + list(map(expand, profile["install"])), env=env)
    if profile.get("no_deps"):
        run(install + ["--no-deps"] + list(map(expand, profile["no_deps"])), env=env)
    # Replace the released dependency even if the downstream pins another version.
    run(install + ["--reinstall-package", "gitpython", "-e", str(CHECKOUT)], env=env)

    # Check the import used by tests and by downstream Python subprocesses.
    run(
        [
            str(python),
            "-c",
            "import os, pathlib, git; "
            "expected = pathlib.Path(os.environ['GITPYTHON_CHECKOUT']) / 'git' / '__init__.py'; "
            "assert pathlib.Path(git.__file__).resolve() == expected.resolve(), git.__file__; "
            "print('GitPython:', git.__file__); print(git.Git().version()); "
            "assert git.Git().version_info >= (2, 52), 'Git 2.52 or newer is required'",
        ],
        cwd=source,
        env=env,
    )
    with (work / "requirements-frozen.txt").open("w") as output:
        run(["uv", "pip", "freeze", "--python", str(python)], env=env, stdout=output)
    result = {"project": args.project, "version": version, "source": provenance, "gitpython": str(CHECKOUT)}
    result_path = work / "result.json"
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    report = work / "junit.xml"
    # Bandit's CLI tests inspect sys.argv and reserve the short spelling `-o`.
    command = [str(python), "-m", "pytest", "-q", "--override-ini=addopts=", "--tb=short", f"--junitxml={report}"]
    command += list(map(expand, profile["tests"])) + profile.get("pytest_args", [])
    completed = run(command, cwd=source / profile.get("cwd", ""), env=env, check=False)
    result["exit_code"] = completed.returncode
    if report.exists():
        cases = list(ET.parse(report).iter("testcase"))
        result["passed"] = sum(
            not any(case.find(tag) is not None for tag in ("failure", "error", "skipped")) for case in cases
        )
        result["skipped"] = sum(case.find("skipped") is not None for case in cases)
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)
    if completed.returncode:
        return completed.returncode
    if not result.get("passed"):
        raise RuntimeError("No downstream tests passed; an empty or entirely skipped suite is not validation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
