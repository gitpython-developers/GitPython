from pathlib import Path

import pytest

from git import Repo
from gitdb.exc import BadName


def _write(repo, path, content):
    full_path = Path(repo.working_tree_dir) / path
    full_path.parent.mkdir(parents=True, exist_ok=True)
    full_path.write_text(content)
    repo.index.add([str(full_path)])


@pytest.fixture
def rev_parse_repo(tmp_path):
    repo = Repo.init(tmp_path)
    with repo.config_writer() as writer:
        writer.set_value("user", "name", "GitPython Tests")
        writer.set_value("user", "email", "gitpython@example.com")

    _write(repo, "README.md", "root\n")
    _write(repo, "CHANGES", "root changes\n")
    _write(repo, "dir/file.txt", "root file\n")
    root = repo.index.commit("root commit")
    repo.create_tag("ann", ref=root, message="annotated tag")

    _write(repo, "README.md", "release\n")
    release = repo.index.commit("release candidate")
    repo.create_tag("v1.0", ref=release)
    main = repo.active_branch

    side = repo.create_head("side", root)
    side.checkout()
    _write(repo, "side.txt", "side\n")
    side_commit = repo.index.commit("side branch")

    main.checkout()
    repo.git.merge("--no-ff", "side", "-m", "merge side")
    merge = repo.head.commit

    repo.create_head("aaaaaaaa", merge)
    repo.create_tag("@foo", ref=merge)

    return {
        "repo": repo,
        "root": root,
        "release": release,
        "side": side_commit,
        "merge": merge,
        "main": main,
    }


def test_rev_parse_names_hex_and_describe_forms(rev_parse_repo):
    repo = rev_parse_repo["repo"]
    merge = rev_parse_repo["merge"]

    assert repo.rev_parse("@") == merge
    assert repo.rev_parse("@foo") == merge
    assert repo.rev_parse("aaaaaaaa") == merge
    assert repo.rev_parse(merge.hexsha[:7]) == merge
    assert repo.rev_parse("v1.0-1-g%s" % merge.hexsha[:7]) == merge
    assert repo.rev_parse("anything-9-g%s" % merge.hexsha[:7]) == merge
    assert repo.rev_parse("%s-dirty" % merge.hexsha[:7]) == merge


def test_rev_parse_navigation_and_peeling(rev_parse_repo):
    repo = rev_parse_repo["repo"]
    root = rev_parse_repo["root"]
    release = rev_parse_repo["release"]
    side = rev_parse_repo["side"]
    merge = rev_parse_repo["merge"]
    tag = repo.rev_parse("ann")

    assert repo.rev_parse("HEAD^0") == merge
    assert repo.rev_parse("HEAD~0") == merge
    assert repo.rev_parse("HEAD^1") == release
    assert repo.rev_parse("HEAD^2") == side
    assert repo.rev_parse("HEAD~") == release
    assert repo.rev_parse("HEAD^^") == root

    assert tag.type == "tag"
    assert repo.rev_parse("ann^{object}") == tag
    assert repo.rev_parse("ann^{tag}") == tag
    assert repo.rev_parse("ann^{}") == root
    assert repo.rev_parse("ann^{commit}") == root
    assert repo.rev_parse("HEAD^{tree}") == merge.tree
    assert repo.rev_parse("HEAD^{/}") == merge


def test_rev_parse_tree_and_index_paths(rev_parse_repo):
    repo = rev_parse_repo["repo"]
    merge = rev_parse_repo["merge"]

    assert repo.rev_parse("HEAD:") == merge.tree
    assert repo.rev_parse("HEAD:README.md") == merge.tree["README.md"]
    assert repo.rev_parse("HEAD^{tree}:README.md") == merge.tree["README.md"]
    assert repo.rev_parse(":README.md").binsha == merge.tree["README.md"].binsha
    assert repo.rev_parse(":0:README.md").binsha == merge.tree["README.md"].binsha


def test_rev_parse_reflog_selectors(rev_parse_repo):
    repo = rev_parse_repo["repo"]
    merge = rev_parse_repo["merge"]
    side = rev_parse_repo["side"]
    main = rev_parse_repo["main"]
    release = rev_parse_repo["release"]

    assert repo.rev_parse("@{0}") == merge
    assert repo.rev_parse("@{+0}") == merge
    assert repo.rev_parse("@{1}") == release
    assert repo.rev_parse("%s@{0}" % main.name) == merge
    assert repo.rev_parse("@{-1}") == side


def test_rev_parse_commit_message_search(rev_parse_repo):
    repo = rev_parse_repo["repo"]
    release = rev_parse_repo["release"]
    merge = rev_parse_repo["merge"]

    assert repo.rev_parse(":/release") == release
    assert repo.rev_parse("HEAD^{/release}") == release
    assert repo.rev_parse("HEAD^{/!-release}") == merge


def test_rev_parse_rejects_invalid_object_specs(rev_parse_repo):
    repo = rev_parse_repo["repo"]

    with pytest.raises(ValueError):
        repo.rev_parse(":")
    with pytest.raises(ValueError):
        repo.rev_parse(":/")
    with pytest.raises(ValueError):
        repo.rev_parse("@{-0}")
    with pytest.raises(ValueError):
        repo.rev_parse("HEAD^{invalid}")
    with pytest.raises(BadName):
        repo.rev_parse(":missing")
