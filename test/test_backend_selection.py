"""Fixture tooling is available independently of the selected backend."""

import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize("backend", ["cli", "gix"])
def test_backend_selection_leaves_fixture_tools_available(backend):
    result = subprocess.check_output(
        [sys.executable, "-c", "from git import _backend; from gix import testtools; print(_backend.name)"],
        env={**os.environ, "GIT_PYTHON_BACKEND": backend},
        text=True,
    )
    assert result.strip() == backend


def test_unknown_backend_is_rejected():
    result = subprocess.run(
        [sys.executable, "-c", "import git"],
        env={**os.environ, "GIT_PYTHON_BACKEND": "unknown"},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "GIT_PYTHON_BACKEND must be 'cli' or 'gix'" in result.stderr
