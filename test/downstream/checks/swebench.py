"""Supplemental checks: SWE-bench 5.0.2 ships no tests for its GitPython callers.

Import the ordinary upstream utility module. The minimal environment only needs
chardet and GitPython; no SWE-bench code or imported module is replaced.
"""

import subprocess
from pathlib import Path

import pytest
from git import Repo
from swebench.inference.make_datasets.utils import (
    AutoContextManager,
    ingest_directory_contents,
)


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("ref_format", ["files", "reftable"])
def test_auto_context_manager_clones_and_resets(tmp_path, monkeypatch, object_format, ref_format):
    """Clone, revisit commits and reuse the checkout with real GitPython."""
    origin = tmp_path / "origin"
    origin.mkdir()
    config = tmp_path / "gitconfig"
    config.write_text("[user]\n name = GitPython Compatibility\n email = tests@example.invalid\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_DEFAULT_REF_FORMAT", ref_format)
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "file")
    monkeypatch.setenv("GIT_TERMINAL_PROMPT", "0")

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(origin), *args], check=True, text=True, capture_output=True
        ).stdout.strip()

    git("init", "-b", "main", f"--object-format={object_format}", f"--ref-format={ref_format}")
    (origin / "README.md").write_text("Local fixture\n")
    (origin / "module.py").write_text("value = 1\n")
    git("add", "--", "README.md", "module.py")
    git("commit", "-m", "initial")
    first_commit = git("rev-parse", "HEAD")
    (origin / "module.py").write_text("value = 2\n")
    git("commit", "-am", "second")
    second_commit = git("rev-parse", "HEAD")

    # Preserve SWE-bench's ordinary HTTPS URL construction while routing the
    # transport to our local fixture. No network access or credentials are used.
    git(
        "config",
        "--global",
        f"url.{origin.as_uri()}.insteadOf",
        "https://gitpython-tests@github.com/swe-bench-repos/fixture__project.git",
    )
    git("config", "--global", "protocol.file.allow", "always")
    root = tmp_path / "checkouts"
    root.mkdir()
    instance = {"repo": "fixture/project", "base_commit": first_commit}
    original_cwd = Path.cwd()
    manager = AutoContextManager(instance, root_dir=str(root), token="gitpython-tests")
    checkout = Path(manager.repo_path)
    with manager as context:
        assert Path.cwd() == checkout
        assert context.get_readme_files() == ["README.md"]
        assert ingest_directory_contents(checkout, include_tests=True) == {"module.py": "value = 1\n"}
        with Repo(checkout) as repo:
            assert repo.head.commit.hexsha == first_commit
            assert repo.git.rev_parse("--show-object-format") == object_format
            assert repo.git.rev_parse("--show-ref-format") == ref_format
    assert Path.cwd() == original_cwd

    # Reuse the local clone even when its source no longer exists. Reset must
    # remove both modified tracked contents and untracked files from a prior run.
    origin.rename(tmp_path / "unavailable-origin")
    (checkout / "module.py").write_text("dirty = True\n")
    (checkout / "untracked.py").write_text("untracked = True\n")
    instance["base_commit"] = second_commit
    with AutoContextManager(instance, root_dir=str(root), token="gitpython-tests") as context:
        assert Path(context.repo_path) == checkout
        assert ingest_directory_contents(checkout, include_tests=True) == {"module.py": "value = 2\n"}
    assert Path.cwd() == original_cwd
