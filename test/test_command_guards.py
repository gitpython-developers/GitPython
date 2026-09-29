"""Command wrappers apply safety checks before starting Git."""

from pathlib import Path
from unittest import mock

import pytest

from git import Actor, Git, GitCommandError, Repo
from git.exc import UnsafeOptionError, UnsafeProtocolError


@pytest.mark.parametrize("allow_unsafe_options", [False, True])
@pytest.mark.parametrize(
    "args, kwargs",
    [
        (("ext::helper",), {}),
        (("ext::",), {}),
        (("custom::address",), {}),
        (("1custom+v2.test-name::address",), {}),
        (("::address",), {}),
        (("custom::\naddress",), {}),
        ((["--refs", ("ext::helper",)],), {}),
        ((None, "--", "ext::helper", "HEAD"), {}),
        ((Path("ext::helper"),), {}),
        ((), {"q": "ext::helper"}),
        ((), {"h": ["ext::helper"]}),
        ((), {"-": "ext::helper"}),
        ((), {"o": [True, "ext::helper"]}),
        (("--server-option",), {"o": "ext::helper", "insert_kwargs_after": "--server-option"}),
    ],
)
def test_ls_remote_rejects_unsafe_protocols(args, kwargs, allow_unsafe_options):
    with mock.patch.object(Git, "execute", side_effect=AssertionError("Git must not run")) as run:
        with pytest.raises(UnsafeProtocolError):
            Git().ls_remote(*args, allow_unsafe_options=allow_unsafe_options, **kwargs)
        run.assert_not_called()


@pytest.mark.parametrize("through_repo", (False, True))
@pytest.mark.parametrize("remote", ("ext::helper", "ext://helper"))
def test_ls_remote_protocol_guard_at_both_entry_points(tmp_path, through_repo, remote):
    with Repo.init(tmp_path) as repo:
        command = repo.git if through_repo else Git()
        with mock.patch.object(Git, "execute", return_value="refs") as execute:
            for allow_unsafe_options in (False, True):
                with pytest.raises(UnsafeProtocolError):
                    command.ls_remote(remote, allow_unsafe_options=allow_unsafe_options)
            execute.assert_not_called()

            url = "ssh://git@[2001:db8::1]/repo.git"
            assert command.ls_remote(url) == "refs"
            execute.assert_called_once_with([Git.GIT_PYTHON_GIT_EXECUTABLE, "ls-remote", url])
            execute.reset_mock()

            with pytest.raises(UnsafeOptionError):
                command.ls_remote(remote, upload_pack="helper", allow_unsafe_protocols=True)
            execute.assert_not_called()
            assert command.ls_remote(remote, allow_unsafe_protocols=True) == "refs"
            execute.assert_called_once_with([Git.GIT_PYTHON_GIT_EXECUTABLE, "ls-remote", remote])


@pytest.mark.parametrize(
    "args, kwargs",
    [
        ((), {}),
        ((None,), {}),
        (("origin", "HEAD"), {"h": True}),
        (("https://example.com/repo.git",), {}),
        (("git@example.com:repo.git",), {}),
        (("origin",), {"o": "key=value"}),
        (("origin",), {"server_option": "key::value"}),
    ],
)
def test_ls_remote_preserves_safe_arguments(args, kwargs):
    with mock.patch.object(Git, "execute", return_value="refs") as run:
        assert Git().ls_remote(*args, **kwargs) == "refs"
        run.assert_called_once()


@pytest.mark.parametrize(
    "url",
    [
        "https://[::1]/repo.git",
        "ssh://git@[2001:db8::1]/repo.git",
        "https://example.com/repo::name",
        "git@example.com:repo::name",
        "./repo::name",
    ],
)
def test_ls_remote_preserves_double_colons_outside_helper_selector(url):
    assert Git().ls_remote(url, get_url=True) == url


def test_ls_remote_unsafe_opt_ins_are_independent():
    with mock.patch.object(Git, "execute", return_value="refs") as run:
        with pytest.raises(UnsafeOptionError):
            Git().ls_remote("origin", upload_pack="helper", allow_unsafe_protocols=True)
        run.assert_not_called()
        assert (
            Git().ls_remote("ext::helper", upload_pack="helper", allow_unsafe_protocols=True, allow_unsafe_options=True)
            == "refs"
        )
        run.assert_called_once_with([Git.GIT_PYTHON_GIT_EXECUTABLE, "ls-remote", "--upload-pack=helper", "ext::helper"])


@pytest.mark.parametrize("allow_unsafe_options", [False, True])
@pytest.mark.parametrize(
    "revs, kwargs",
    [
        (("HEAD", "--output=unused"), {}),
        (("HEAD", ["--out=unused"]), {}),
        (("HEAD", "-ounused"), {}),
        (("HEAD", "HEAD"), {"output": "unused"}),
        (("HEAD", "HEAD"), {"out": "unused"}),
        (("HEAD", "HEAD"), {"o": "unused"}),
    ],
)
def test_merge_base_checks_unsafe_options(tmp_path, revs, kwargs, allow_unsafe_options):
    repo = Repo.init(tmp_path)
    with mock.patch.object(Git, "execute", return_value="") as run:
        if allow_unsafe_options:
            assert repo.merge_base(*revs, allow_unsafe_options=True, **kwargs) == []
            run.assert_called_once()
            assert "--allow-unsafe-options" not in run.call_args[0][0]
        else:
            with pytest.raises(UnsafeOptionError):
                repo.merge_base(*revs, **kwargs)
            run.assert_not_called()


@pytest.mark.parametrize("status", [-9, 2, 128, 129])
def test_merge_base_propagates_errors(tmp_path, status):
    repo = Repo.init(tmp_path)
    error = GitCommandError("git merge-base", status)
    with mock.patch.object(Git, "execute", side_effect=error):
        with pytest.raises(GitCommandError) as raised:
            repo.merge_base("HEAD", "HEAD")
        assert raised.value is error


def test_merge_base_distinguishes_unrelated_history_from_invalid_options(tmp_path):
    repo = Repo.init(tmp_path)
    actor = Actor("Test", "test@example.com")
    first = repo.index.commit("first", author=actor, committer=actor)
    second = repo.index.commit("second", parent_commits=[], head=False, author=actor, committer=actor)
    assert repo.merge_base(first, first) == [first]
    assert repo.merge_base(first, second) == []
    with pytest.raises(GitCommandError) as raised:
        repo.merge_base(first, second, invalid_option=True)
    assert raised.value.status == 129


@pytest.mark.parametrize("allow_unsafe_options", [False, True])
@pytest.mark.parametrize("option", ["pathspec_from_file", "pathspec-from-file", "pathspec_from"])
@pytest.mark.parametrize("dry_run", [False, True])
def test_move_checks_unsafe_options(tmp_path, option, dry_run, allow_unsafe_options):
    repo = Repo.init(tmp_path)
    with mock.patch.object(Git, "execute", return_value="Renaming source to destination\n") as run:
        kwargs = {option: "unused", "dry_run": dry_run}
        if allow_unsafe_options:
            assert repo.index.move(["source", "destination"], True, allow_unsafe_options=True, **kwargs) == [
                ("source", "destination")
            ]
            assert run.call_count == (1 if dry_run else 2)
            for call in run.call_args_list:
                argv = call[0][0]
                assert "-k" in argv
                assert f"--{option.replace('_', '-')}=unused" in argv
                assert "--allow-unsafe-options" not in argv
                assert argv[-3:] == ["--", "source", "destination"]
        else:
            with pytest.raises(UnsafeOptionError):
                repo.index.move(["source", "destination"], **kwargs)
            run.assert_not_called()
