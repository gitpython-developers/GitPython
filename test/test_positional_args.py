"""High-level operands must not become Git options."""

from unittest import mock

import pytest

from git import Git, Remote, Repo
from git.exc import UnsafeOptionError


@pytest.mark.parametrize("allow_unsafe_options", [False, True])
@pytest.mark.parametrize(
    "refspec",
    ["--upload-pack=helper", ["--upl=helper"], ["main", "--dry-run"], "-uhelper", "--arg value", "--"],
)
def test_pull_rejects_option_shaped_refspec(tmp_path, refspec, allow_unsafe_options):
    repo = Repo.init(tmp_path)
    remote = Remote(repo, "origin")
    with mock.patch.object(Git, "_call_process", side_effect=AssertionError("Git must not run")) as run:
        with pytest.raises(UnsafeOptionError):
            remote.pull(refspec, allow_unsafe_options=allow_unsafe_options)
        run.assert_not_called()


def test_pull_rejects_option_shaped_remote(tmp_path):
    repo = Repo.init(tmp_path)
    remote = Remote(repo, "--upload-pack=helper")
    with mock.patch.object(Git, "_call_process", side_effect=AssertionError("Git must not run")) as run:
        with pytest.raises(UnsafeOptionError):
            remote.pull("main")
        run.assert_not_called()


def test_pull_preserves_operand_and_explicit_option_values(tmp_path):
    repo = Repo.init(tmp_path)
    remote = Remote(repo, "origin")
    with mock.patch.object(Git, "_call_process") as run, mock.patch.object(
        Remote, "_get_fetch_info_from_stderr", return_value=[]
    ):
        remote.pull("refs/heads/topic", upload_pack="helper with spaces", allow_unsafe_options=True)
    assert run.call_args[0] == ("pull", "--", remote, ["refs/heads/topic"])
    assert run.call_args[1]["upload_pack"] == "helper with spaces"
