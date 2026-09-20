# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

from functools import partial
from pathlib import Path
from unittest import mock

import pytest

from git import Git, Remote, Repo, RootModule, Submodule
from git.exc import GitCommandError


def _commit_file(repo, content):
    Path(repo.working_tree_dir, "file").write_text(content, encoding="utf-8")
    repo.index.add(["file"])
    return repo.index.commit("Write " + content)


def _cached_remote_refs(repo):
    return {ref.path: ref.commit.hexsha for remote in repo.remotes for ref in remote.refs}


@pytest.fixture
def local_submodule(tmp_path):
    """Use only local repositories, with two commits already available in the clone."""
    with Repo.init(tmp_path / "source") as source, Repo.init(tmp_path / "parent") as parent:
        # RootModule's URL-change handling currently assumes a master branch.
        source.git.symbolic_ref("HEAD", "refs/heads/master")
        _commit_file(source, "initial")
        _commit_file(source, "cached")
        submodule = parent.create_submodule(
            "module", "module", source.working_tree_dir, branch=source.head.reference.name
        )
        parent.index.commit("Add submodule")
        with submodule.module() as module:
            yield submodule, source, module


@pytest.fixture(params=["submodule", "root", "repo"])
def update_submodule(request, local_submodule):
    submodule, _, _ = local_submodule
    if request.param == "submodule":
        return submodule.update
    if request.param == "root":
        update = RootModule(submodule.repo).update
    else:
        update = submodule.repo.submodule_update
    return partial(update, previous_commit=submodule.repo.head.commit, recursive=False)


@pytest.fixture(params=["missing", "deinitialized"])
def uninitialized_submodule(request, local_submodule):
    submodule, _, module = local_submodule
    metadata = Path(module.git_dir)
    module.close()
    if request.param == "deinitialized":
        submodule.deinit()
    else:
        submodule.remove(configuration=False, force=True)
    assert not submodule.module_exists()
    assert metadata.is_dir() == (request.param == "deinitialized")
    return submodule, metadata


@pytest.mark.parametrize("no_fetch", [None, False, True], ids=["default", "fetch", "no-fetch"])
def test_update_no_fetch_checks_out_cached_commit(local_submodule, update_submodule, no_fetch):
    submodule, source, module = local_submodule
    module.create_remote("backup", source.working_tree_dir)
    module.head.reset("HEAD~1", index=True, working_tree=True)
    assert module.head.commit.binsha != submodule.binsha
    options = {} if no_fetch is None else {"no_fetch": no_fetch}

    with mock.patch.object(Remote, "fetch", autospec=True, side_effect=Remote.fetch) as fetch:
        update_submodule(**options)

    assert module.head.commit.binsha == submodule.binsha
    assert Path(submodule.abspath, "file").read_text(encoding="utf-8") == "cached"
    assert fetch.call_count == (0 if no_fetch else 2)
    assert {call[0][0].name for call in fetch.call_args_list} == (set() if no_fetch else {"origin", "backup"})


def test_update_no_fetch_to_latest_revision_uses_cached_tip(local_submodule, update_submodule):
    submodule, source, module = local_submodule
    cached_tip = module.head.reference.tracking_branch().commit
    module.head.reset("HEAD~1", index=True, working_tree=True)
    submodule.binsha = module.head.commit.binsha
    submodule.repo.index.add([submodule])
    submodule.repo.index.commit("Pin submodule to initial commit")
    remote_tip = _commit_file(source, "remote-only")
    assert submodule.binsha != cached_tip.binsha != remote_tip.binsha

    with mock.patch.object(Remote, "fetch", side_effect=AssertionError("Unexpected fetch")) as fetch:
        update_submodule(no_fetch=True, to_latest_revision=True)

    fetch.assert_not_called()
    assert module.head.commit == cached_tip
    assert module.head.reference.tracking_branch().commit == cached_tip
    assert Path(submodule.abspath, "file").read_text(encoding="utf-8") == "cached"


def test_update_no_fetch_cannot_check_out_missing_commit(local_submodule, update_submodule):
    submodule, source, module = local_submodule
    cached_tip = module.head.commit
    submodule.binsha = _commit_file(source, "remote-only").binsha
    submodule.repo.index.add([submodule])
    submodule.repo.index.commit("Pin submodule to uncached commit")

    with mock.patch.object(Remote, "fetch", side_effect=AssertionError("Unexpected fetch")) as fetch:
        with pytest.raises(GitCommandError, match="merge-base"):
            update_submodule(no_fetch=True)

    fetch.assert_not_called()
    assert module.head.commit == cached_tip
    assert module.head.reference.tracking_branch().commit == cached_tip
    assert Path(submodule.abspath, "file").read_text(encoding="utf-8") == "cached"


@pytest.mark.parametrize("uninitialized_submodule", ["missing"], indirect=True)
@pytest.mark.parametrize("keep_going", [False, True], ids=["raise", "keep-going"])
def test_update_no_fetch_rejects_missing_submodule(uninitialized_submodule, update_submodule, keep_going, caplog):
    submodule, metadata = uninitialized_submodule
    parent_config = Path(submodule.repo.git_dir, "config").read_bytes()

    with mock.patch.object(Remote, "fetch") as fetch, mock.patch.object(Submodule, "_clone_repo") as clone:
        if keep_going:
            update_submodule(no_fetch=True, keep_going=True)
            assert "fetching is disabled" in caplog.text
        else:
            with pytest.raises(ValueError, match="fetching is disabled"):
                update_submodule(no_fetch=True)

    fetch.assert_not_called()
    clone.assert_not_called()
    assert not submodule.module_exists()
    assert not Path(submodule.abspath, ".git").exists()
    assert not metadata.exists()
    assert Path(submodule.repo.git_dir, "config").read_bytes() == parent_config


@pytest.mark.parametrize(
    "options",
    [
        pytest.param({"init": False}, id="init-false"),
        pytest.param({"dry_run": True}, id="dry-run"),
    ],
)
def test_update_no_fetch_can_skip_uninitialized_submodule(uninitialized_submodule, update_submodule, options):
    submodule, metadata = uninitialized_submodule
    retained_metadata = metadata.is_dir()
    parent_config = Path(submodule.repo.git_dir, "config").read_bytes()

    with mock.patch.object(Remote, "fetch") as fetch, mock.patch.object(Submodule, "_clone_repo") as clone:
        update_submodule(no_fetch=True, **options)

    fetch.assert_not_called()
    clone.assert_not_called()
    assert not submodule.module_exists()
    assert not Path(submodule.abspath, ".git").exists()
    assert metadata.is_dir() == retained_metadata
    assert Path(submodule.repo.git_dir, "config").read_bytes() == parent_config


@pytest.mark.parametrize("to_latest_revision", [False, True], ids=["gitlink", "cached-tip"])
@pytest.mark.parametrize("keep_going", [False, True], ids=["raise", "keep-going"])
def test_update_no_fetch_restores_deinitialized_submodule(
    local_submodule, update_submodule, to_latest_revision, keep_going, caplog
):
    submodule, source, module = local_submodule
    tracking_branch = module.head.reference.tracking_branch()
    cached_tip = tracking_branch.commit
    branch_path = module.head.reference.path
    cached_refs = _cached_remote_refs(module)
    module.head.reset("HEAD~1", index=True, working_tree=True)
    assert module.head.commit != cached_tip
    if to_latest_revision:
        submodule.binsha = module.head.commit.binsha
        submodule.repo.index.add([submodule])
        submodule.repo.index.commit("Pin submodule to initial commit")
        assert submodule.binsha != cached_tip.binsha

    metadata = Path(module.git_dir)
    module.close()
    submodule.deinit(force=True)
    assert not submodule.module_exists()
    assert metadata.is_dir()
    remote_tip = _commit_file(source, "remote-only")
    assert remote_tip != cached_tip

    with mock.patch.object(Remote, "fetch") as fetch, mock.patch.object(Submodule, "_clone_repo") as clone:
        update_submodule(no_fetch=True, to_latest_revision=to_latest_revision, keep_going=keep_going)

    fetch.assert_not_called()
    clone.assert_not_called()
    assert not caplog.records
    assert submodule.module_exists()
    assert Path(submodule.abspath, ".git").is_file()
    with submodule.module() as restored:
        assert Path(restored.git_dir).samefile(metadata)
        assert restored.head.commit == cached_tip
        assert restored.head.reference.path == branch_path
        assert restored.head.reference.tracking_branch().path == tracking_branch.path
        assert _cached_remote_refs(restored) == cached_refs
        assert Path(submodule.abspath, "file").read_text(encoding="utf-8") == "cached"
        assert not restored.is_dirty(untracked_files=True)
    with submodule.repo.config_reader() as reader:
        assert reader.get_value(f'submodule "{submodule.name}"', "url") == submodule.url


@pytest.mark.parametrize("no_fetch", [None, False], ids=["default", "fetch"])
def test_update_after_deinit_fetches_remote_tip(local_submodule, update_submodule, no_fetch):
    submodule, source, module = local_submodule
    metadata = Path(module.git_dir)
    module.close()
    submodule.deinit()
    remote_tip = _commit_file(source, "remote-only")
    options = {} if no_fetch is None else {"no_fetch": no_fetch}

    with mock.patch.object(Remote, "fetch", autospec=True, side_effect=Remote.fetch) as fetch:
        with mock.patch.object(Submodule, "_clone_repo") as clone:
            update_submodule(to_latest_revision=True, **options)

    clone.assert_not_called()
    fetch.assert_called_once()
    assert fetch.call_args[0][0].name == "origin"
    assert Path(fetch.call_args[0][0].repo.git_dir).samefile(metadata)
    with submodule.module() as restored:
        assert Path(restored.git_dir).samefile(metadata)
        assert restored.head.commit == remote_tip
        assert restored.head.reference.tracking_branch().commit == remote_tip
        assert Path(submodule.abspath, "file").read_text(encoding="utf-8") == "remote-only"


@pytest.mark.parametrize("uninitialized_submodule", ["deinitialized"], indirect=True)
def test_update_no_fetch_preserves_nonempty_deinitialized_checkout(uninitialized_submodule, update_submodule):
    submodule, metadata = uninitialized_submodule
    checkout_file = Path(submodule.abspath, "file")
    checkout_file.write_text("user content", encoding="utf-8")
    parent_config = Path(submodule.repo.git_dir, "config").read_bytes()

    with mock.patch.object(Remote, "fetch") as fetch, mock.patch.object(Submodule, "_clone_repo") as clone:
        with pytest.raises(OSError, match="does already exist and is non-empty"):
            update_submodule(no_fetch=True)

    fetch.assert_not_called()
    clone.assert_not_called()
    assert checkout_file.read_text(encoding="utf-8") == "user content"
    assert not Path(submodule.abspath, ".git").exists()
    assert metadata.is_dir()
    assert Path(submodule.repo.git_dir, "config").read_bytes() == parent_config


@pytest.mark.parametrize("no_fetch", [False, True], ids=["fetch", "no-fetch"])
def test_update_no_fetch_is_recursive(local_submodule, update_submodule, no_fetch):
    submodule, source, module = local_submodule
    child = module.create_submodule("nested", "nested", source.working_tree_dir, branch=source.head.reference.name)
    with child.module() as nested:
        cached_tip = nested.head.commit
        nested.head.reset("HEAD~1", index=True, working_tree=True)
        child.binsha = nested.head.commit.binsha
        module.index.add([child])
        previous = module.index.commit("Add nested submodule at initial commit")
        child.binsha = cached_tip.binsha
        module.index.add([child])
        target = module.index.commit("Advance nested submodule")
        submodule.binsha = target.binsha
        submodule.repo.index.add([submodule])
        submodule.repo.index.commit("Record nested submodule update")
        module.head.reset(previous, index=True, working_tree=True)

        with mock.patch.object(Remote, "fetch", autospec=True, side_effect=Remote.fetch) as fetch:
            update_submodule(recursive=True, no_fetch=no_fetch)

        assert module.head.commit == target
        assert nested.head.commit == cached_tip
        assert Path(child.abspath, "file").read_text(encoding="utf-8") == "cached"
        assert fetch.call_count == (0 if no_fetch else 2)
        assert {call[0][0].repo.git_dir for call in fetch.call_args_list} == (
            set() if no_fetch else {module.git_dir, nested.git_dir}
        )


@pytest.mark.parametrize("no_fetch", [False, True], ids=["fetch", "no-fetch"])
def test_root_update_no_fetch_on_branch_change(local_submodule, no_fetch):
    submodule, source, module = local_submodule
    branch_name = source.head.reference.name + "-other"
    source.create_head(branch_name)
    module.remotes.origin.fetch()
    tracking_branch = module.remotes.origin.refs[branch_name]
    previous = submodule.repo.head.commit
    with submodule.config_writer() as writer:
        writer.set_value("branch", branch_name)
    submodule.repo.index.commit("Change submodule branch")
    module.head.reset("HEAD~1", index=True, working_tree=True)

    with mock.patch.object(Remote, "fetch", autospec=True, side_effect=Remote.fetch) as fetch:
        RootModule(submodule.repo).update(previous_commit=previous, recursive=False, no_fetch=no_fetch)

    assert module.head.reference.name == branch_name
    assert module.head.reference.tracking_branch() == tracking_branch
    assert module.head.commit.binsha == submodule.binsha
    if no_fetch:
        fetch.assert_not_called()
    else:
        assert fetch.called


@pytest.mark.parametrize("no_fetch", [False, True], ids=["fetch", "no-fetch"])
def test_root_update_no_fetch_on_url_change(local_submodule, tmp_path, no_fetch):
    submodule, source, module = local_submodule
    previous = submodule.repo.head.commit
    branch_path = module.head.reference.path
    tracking_branch = module.head.reference.tracking_branch()
    cached_refs = _cached_remote_refs(module)
    module.head.reset("HEAD~1", index=True, working_tree=True)
    assert module.head.commit.binsha != submodule.binsha
    with source.clone(tmp_path / "mirror") as mirror:
        mirror_url = Git.polish_url(mirror.working_tree_dir)
        with submodule.config_writer() as writer:
            writer.set_value("url", mirror_url)
        submodule.repo.index.commit("Change submodule URL")

        with mock.patch.object(Remote, "fetch", autospec=True, side_effect=Remote.fetch) as fetch:
            RootModule(submodule.repo).update(previous_commit=previous, recursive=False, no_fetch=no_fetch)

        if no_fetch:
            fetch.assert_not_called()
            assert module.head.reference.path == branch_path
            assert module.head.reference.tracking_branch() == tracking_branch
            assert _cached_remote_refs(module) == cached_refs
        else:
            assert fetch.call_count == 2
            assert {call[0][0].name for call in fetch.call_args_list} == {"origin"}
        assert module.remotes.origin.url == mirror_url
        assert {remote.name for remote in module.remotes} == {"origin"}

    assert module.head.commit.binsha == submodule.binsha
    assert Path(submodule.abspath, "file").read_text(encoding="utf-8") == "cached"


@pytest.mark.parametrize("change_branch", [False, True], ids=["same-branch", "branch-change"])
def test_root_update_no_fetch_url_change_uses_cached_tip(local_submodule, tmp_path, change_branch):
    submodule, source, module = local_submodule
    branch_name = source.head.reference.name
    if change_branch:
        branch_name += "-other"
        source.create_head(branch_name)
        module.remotes.origin.fetch()
    tracking_branch = module.remotes.origin.refs[branch_name]
    cached_tip = tracking_branch.commit
    cached_refs = _cached_remote_refs(module)
    module.head.reset("HEAD~1", index=True, working_tree=True)
    submodule.binsha = module.head.commit.binsha
    submodule.repo.index.add([submodule])
    previous = submodule.repo.index.commit("Pin submodule to initial commit")
    assert submodule.binsha != cached_tip.binsha

    with source.clone(tmp_path / "mirror") as mirror:
        if change_branch:
            mirror.create_head(branch_name).checkout()
        remote_tip = _commit_file(mirror, "remote-only")
        assert remote_tip != cached_tip
        mirror_url = Git.polish_url(mirror.working_tree_dir)
        with submodule.config_writer() as writer:
            writer.set_value("url", mirror_url)
            writer.set_value("branch", branch_name)
        submodule.repo.index.commit("Change submodule URL and tracking branch")

        with mock.patch.object(Remote, "fetch", side_effect=AssertionError("Unexpected fetch")) as fetch:
            RootModule(submodule.repo).update(
                previous_commit=previous, recursive=False, no_fetch=True, to_latest_revision=True
            )

        fetch.assert_not_called()
        assert module.remotes.origin.url == mirror_url
        assert {remote.name for remote in module.remotes} == {"origin"}
        assert _cached_remote_refs(module) == cached_refs
        assert module.head.reference.name == branch_name
        assert module.head.reference.tracking_branch() == tracking_branch
        assert module.head.commit == cached_tip
        assert Path(submodule.abspath, "file").read_text(encoding="utf-8") == "cached"


@pytest.mark.parametrize("multiple_remotes", [False, True], ids=["single-remote-fallback", "matching-remote"])
def test_root_update_no_fetch_selects_url_change_remote(local_submodule, tmp_path, multiple_remotes):
    submodule, source, module = local_submodule
    previous = submodule.repo.head.commit
    original_url = module.remotes.origin.url
    module.remotes.origin.set_url(Git.polish_url(str(tmp_path / "unrelated")))
    if multiple_remotes:
        upstream = module.create_remote("upstream", original_url)
        upstream.fetch()
        module.head.reference.set_tracking_branch(upstream.refs[submodule.branch_name])
    else:
        module.remotes.origin.rename("upstream")
    tracking_branch = module.head.reference.tracking_branch()
    cached_refs = _cached_remote_refs(module)
    module.head.reset("HEAD~1", index=True, working_tree=True)
    assert module.head.commit.binsha != submodule.binsha

    with source.clone(tmp_path / "mirror") as mirror:
        mirror_url = Git.polish_url(mirror.working_tree_dir)
        expected_urls = {remote.name: remote.url for remote in module.remotes}
        expected_urls["upstream"] = mirror_url
        with submodule.config_writer() as writer:
            writer.set_value("url", mirror_url)
        submodule.repo.index.commit("Change submodule URL")

        with mock.patch.object(Remote, "fetch", side_effect=AssertionError("Unexpected fetch")) as fetch:
            RootModule(submodule.repo).update(previous_commit=previous, recursive=False, no_fetch=True)

        fetch.assert_not_called()
        assert {remote.name: remote.url for remote in module.remotes} == expected_urls
        assert _cached_remote_refs(module) == cached_refs
        assert module.head.reference.tracking_branch() == tracking_branch
        assert module.head.commit.binsha == submodule.binsha
        assert Path(submodule.abspath, "file").read_text(encoding="utf-8") == "cached"
