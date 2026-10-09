"""Fetch and pull derive results exclusively from Git command output."""

import builtins
import os
from unittest import mock

import pytest

from git import FetchInfo, Repo
from git.objects.submodule.util import sm_section


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("ref_format", ["files", "reftable"])
def test_fetch_and_pull_without_reading_fetch_head(tmp_path, object_format, ref_format):
    source = Repo.init(tmp_path / "source", object_format=object_format, ref_format=ref_format)
    identity = {
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    source.git.update_environment(**identity)
    source.git.commit("--no-gpg-sign", "--allow-empty", "-m", "first")
    branch = source.active_branch.name
    clone = Repo.clone_from(str(tmp_path / "source"), tmp_path / "clone")
    clone.git.update_environment(**identity)
    old = clone.head.commit
    source.git.commit("--no-gpg-sign", "--allow-empty", "-m", "second")
    expected = source.head.commit
    original_open = builtins.open

    def checked_open(path, *args, **kwargs):
        if isinstance(path, (str, os.PathLike)):
            assert os.path.basename(path) != "FETCH_HEAD", "Python must not read FETCH_HEAD"
        return original_open(path, *args, **kwargs)

    with mock.patch("builtins.open", side_effect=checked_open):
        result = clone.remote().fetch()
        info = result["origin/" + branch]
        assert info.old_commit == old
        assert info.commit == expected
        assert info.flags & FetchInfo.FAST_FORWARD
        assert info.remote_ref_path == branch
        assert isinstance(info.note, str)
        single = clone.remote().fetch(branch)
        assert len(single) == 1
        assert single[0].ref.path == "FETCH_HEAD"
        assert single[0].commit == expected
        clone.remote().pull(ff_only=True)
        assert clone.head.commit == expected
    source.close()
    clone.close()


def test_quoted_remote_and_submodule_names(tmp_path):
    with Repo.init(tmp_path / "source") as source, Repo.init(tmp_path / "parent") as parent:
        source.index.commit("Initial commit")
        remote = parent.create_remote('quoted"remote', str(tmp_path / "source"))
        assert parent.remote(remote.name).url == remote.url
        assert remote.config_reader.get_value("url") == (tmp_path / "source").as_posix()
        # Keep the quoted name in config: Windows cannot represent it in metadata.
        with Repo.clone_from(str(tmp_path / "source"), tmp_path / "parent" / "module"):
            module = parent.create_submodule("module", "module")
        quoted_name = 'quoted"module'
        with module.config_writer() as writer:
            writer.config.rename_section(sm_section(module.name), sm_section(quoted_name))
        parent.index.commit("Add module")
        module = parent.submodules[0]
        assert module.name == quoted_name
        assert module.config_reader().get_value("url") == (tmp_path / "source").as_posix()
