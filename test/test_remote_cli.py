"""Fetch and pull derive results exclusively from Git command output."""

import builtins
import os
from unittest import mock

import pytest

from git import FetchInfo, Repo, _backend
from git.objects.submodule.util import sm_section
from test.lib.fixtures import writable_fixture


@pytest.fixture
def remote_fixture(request):
    with writable_fixture("remote-cli.sh", *request.param) as temporary:
        yield temporary.path().resolve()


@pytest.mark.parametrize("remote_fixture", [("push-mirror", obj) for obj in ("sha1", "sha256")], indirect=True)
def test_push_uses_mirror_remote_selector(remote_fixture):
    with Repo(remote_fixture / "source") as source, Repo(remote_fixture / "clone") as clone:
        expected = clone.commit("refs/remotes/mirror/main")
        assert expected != clone.commit("refs/remotes/origin/main")
        assert clone.git.rev_parse("--verify", "@{push}") == expected.hexsha
        fallback = ("rev_parse", "CLI: push remote selectors (GIX-46)")
        before = _backend.statistics().get(fallback, 0)

        (info,) = clone.remote("origin").push("@{push}:refs/heads/snapshot")

        assert source.heads.snapshot.commit == expected
        assert info.local_ref is None
        assert info.local_hash == expected.hexsha
        if _backend.name == "gix":
            assert _backend.statistics().get(fallback, 0) == before + 1


@pytest.mark.parametrize(
    "remote_fixture",
    [("fetch", obj, refs) for obj in ("sha1", "sha256") for refs in ("files", "reftable")],
    indirect=True,
)
def test_fetch_and_pull_without_reading_fetch_head(remote_fixture):
    source = Repo(remote_fixture / "source")
    branch = source.active_branch.name
    clone = Repo(remote_fixture / "clone")
    old = clone.head.commit
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


@pytest.mark.parametrize("remote_fixture", [("tag-named-like-branch",)], indirect=True)
def test_fetch_resolves_tag_named_like_a_full_branch_ref(remote_fixture):
    # Git displays refs/tags/refs/heads/main as refs/heads/main.
    with Repo(remote_fixture / "source") as source, Repo(remote_fixture / "clone") as clone:
        branch = clone.heads.main.commit
        [info] = [info for info in clone.remote().fetch() if info.flags & FetchInfo.NEW_TAG]
        assert info.ref.path == "refs/tags/refs/heads/main"
        assert info.commit == source.head.commit
        assert clone.heads.main.commit == branch


@pytest.mark.parametrize("remote_fixture", [("abbreviated-tag-source",)], indirect=True)
def test_fetch_resolves_explicit_destination_that_looks_like_a_local_tag(remote_fixture):
    with Repo(remote_fixture / "source") as source, Repo(remote_fixture / "clone") as clone:
        [info] = clone.remote().fetch("tags/v1:refs/archive/v1", no_tags=True)
        assert info.ref.path == "refs/archive/v1"
        assert info.commit == source.head.commit
        assert clone.tags["refs/archive/v1"].commit == clone.head.commit


@pytest.mark.parametrize("remote_fixture", [("notes-and-tag-wildcards",)], indirect=True)
def test_fetch_resolves_notes_with_a_tag_wildcard(remote_fixture):
    with Repo(remote_fixture / "source") as source, Repo(remote_fixture / "clone") as clone:
        remote = clone.remote()
        for flags in (0, FetchInfo.HEAD_UPTODATE, FetchInfo.FAST_FORWARD):
            if flags == FetchInfo.FAST_FORWARD:
                source.git.update_ref("refs/notes/commits", "refs/fixture/updated-notes")
            [info] = [info for info in remote.fetch() if info.remote_ref_path == "refs/notes/commits"]
            assert info.ref.path == "refs/notes/commits"
            assert info.commit == source.commit("refs/notes/commits")
            assert info.flags == flags


@pytest.mark.parametrize("remote_fixture", [("prefetch",)], indirect=True)
def test_prefetch_indexes_displayed_refs_once(remote_fixture):
    paths = {"refs/prefetch/remotes/origin/main", "refs/prefetch/remotes/origin/second"}
    with Repo(remote_fixture / "clone") as clone:
        with mock.patch.object(FetchInfo, "_display_ref", wraps=FetchInfo._display_ref) as display_ref:
            result = clone.remote().fetch(prefetch=True)
        assert {info.ref.path for info in result} == paths
        assert all(info.flags == FetchInfo.HEAD_UPTODATE for info in result)
        displayed = [args[0] for args, _ in display_ref.call_args_list if args[0] in paths]
        assert len(displayed) == len(set(displayed))


@pytest.mark.parametrize("remote_fixture", [("quoted",)], indirect=True)
def test_quoted_remote_and_submodule_names(remote_fixture):
    tmp_path = remote_fixture
    with Repo(tmp_path / "source"), Repo(tmp_path / "parent") as parent:
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
