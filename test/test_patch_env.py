"""Regression tests for temporary environment variable changes."""

import os

import pytest

from git.util import patch_env


@pytest.mark.parametrize("original", [None, "", "original"])
@pytest.mark.parametrize("change", ["keep", "replace", "delete"])
@pytest.mark.parametrize("raise_error", [False, True])
def test_patch_env_restores_original_state(monkeypatch, original, change, raise_error):
    name = "GITPYTHON_TEST_PATCH_ENV"
    if original is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, original)

    def change_environment():
        with patch_env(name, "temporary"):
            assert os.environ[name] == "temporary"
            if change == "replace":
                os.environ[name] = "changed"
            elif change == "delete":
                del os.environ[name]
            if raise_error:
                raise RuntimeError("context body failed")

    if raise_error:
        with pytest.raises(RuntimeError, match="context body failed"):
            change_environment()
    else:
        change_environment()

    if original is None:
        assert name not in os.environ
    else:
        assert os.environ[name] == original
