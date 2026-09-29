# Copyright (C) 2026 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import subprocess
import sys
from pathlib import Path

import pytest
from gitdb.exc import BadName

from git import Actor, Commit, Repo
from git.refs import RemoteReference, SymbolicReference


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

    _write(repo, "side.txt", "side\n")
    side_commit = repo.index.commit("side branch", parent_commits=[root], head=False, skip_hooks=True)
    repo.create_head("side", side_commit)

    merge = repo.index.commit("merge side", parent_commits=[release, side_commit], skip_hooks=True)
    repo.head.log_append(side_commit.binsha, "checkout: moving from side to main", merge.binsha)

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
    release = rev_parse_repo["release"]
    merge = rev_parse_repo["merge"]

    assert repo.rev_parse("@") == merge
    assert repo.rev_parse("@foo") == merge
    assert repo.rev_parse("aaaaaaaa") == merge
    assert repo.rev_parse(merge.hexsha[:7]) == merge
    describe_name = "anything-9-g%s" % merge.hexsha[:7]
    assert repo.rev_parse("v1.0-1-g%s" % merge.hexsha[:7]) == merge
    assert repo.rev_parse(describe_name) == merge
    assert repo.rev_parse("%s-dirty" % merge.hexsha[:7]) == merge

    repo.create_tag(describe_name, ref=release)
    assert repo.rev_parse(describe_name) == release


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
    with pytest.raises(ValueError):
        repo.rev_parse("HEAD^{/}")


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

    SymbolicReference.create(repo, "refs/remotes/origin/%s" % main.name, merge)
    main.set_tracking_branch(RemoteReference(repo, "refs/remotes/origin/%s" % main.name))
    assert repo.rev_parse("%s@{upstream}" % main.name) == merge


def test_rev_parse_commit_message_search(rev_parse_repo):
    repo = rev_parse_repo["repo"]
    release = rev_parse_repo["release"]
    merge = rev_parse_repo["merge"]

    assert repo.rev_parse(":/release") == release
    assert repo.rev_parse("HEAD^{/release}") == release
    assert repo.rev_parse("HEAD^{/!-release}") == merge


@pytest.mark.parametrize(
    "revision",
    [
        ":/release[[:space:]]candidate",
        "HEAD^{/release{1}}",
        "ann^{/root}",
        ":/!-release",
        "HEAD^{/!-release}",
        "HEAD^{/release}^0",
        "HEAD^{/release}^{tree}",
    ],
)
def test_rev_parse_commit_message_search_matches_git(rev_parse_repo, revision):
    repo = rev_parse_repo["repo"]
    expected = repo.git.rev_parse("--verify", revision)
    assert repo.rev_parse(revision).hexsha == expected


@pytest.mark.parametrize("revision", [":/release", "HEAD^{/release}"])
def test_commit_and_tree_message_search(rev_parse_repo, revision):
    repo = rev_parse_repo["repo"]
    release = rev_parse_repo["release"]
    assert repo.commit(revision) == release
    assert repo.tree(revision) == release.tree


def test_rev_parse_commit_message_literal_bang_and_option(rev_parse_repo):
    repo = rev_parse_repo["repo"]
    commit = repo.index.commit("!urgent --all")
    assert repo.rev_parse(":/!!urgent") == commit
    assert repo.rev_parse("HEAD^{/!!urgent}") == commit
    assert repo.rev_parse(":/--all") == commit
    assert repo.rev_parse("HEAD^{/--all}") == commit


def test_rev_parse_commit_message_escaped_braces(rev_parse_repo):
    repo = rev_parse_repo["repo"]
    commit = repo.index.commit("literal{3}")
    repo.index.commit("literalll")
    assert repo.rev_parse(r"HEAD^{/literal\{3\}}") == commit


def test_revision_message_search_does_not_backtrack_in_python(tmp_path):
    with Repo.init(tmp_path) as repo:
        actor = Actor("GitPython Tests", "gitpython@example.com")
        repo.index.commit("hello " + "b" * 80, author=actor, committer=actor)

    # Run the adversarial expression in a killable process: Python's regex engine
    # can otherwise hold the GIL indefinitely, including against a short message.
    subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
from git import Repo
from gitdb.exc import BadName

with Repo(sys.argv[1]) as repo:
    for resolve in (repo.rev_parse, repo.commit, repo.tree):
        for revision in (':/(.+)+ZZZ', 'HEAD^{/(.+)+ZZZ}'):
            try:
                resolve(revision)
            except BadName:
                pass
            else:
                raise AssertionError('Unexpected match: ' + revision)
""",
            str(tmp_path),
        ],
        check=True,
        capture_output=True,
        timeout=5,
    )


def test_revision_message_search_does_not_deserialize_history(tmp_path, monkeypatch):
    with Repo.init(tmp_path) as repo:
        actor = Actor("GitPython Tests", "gitpython@example.com")
        commit = repo.index.commit("needle", author=actor, committer=actor)

        def reject_deserialization(*args, **kwargs):
            raise AssertionError("Message search must not deserialize commits in Python")

        monkeypatch.setattr(Commit, "_deserialize", reject_deserialization)
        assert repo.rev_parse(":/needle") == commit
        assert repo.rev_parse("HEAD^{/needle}") == commit


def test_commit_and_tree_resolve_before_peeling(rev_parse_repo):
    repo = rev_parse_repo["repo"]
    root = rev_parse_repo["root"]
    merge = rev_parse_repo["merge"]
    assert repo.commit("ann") == root
    assert repo.tree("ann") == root.tree
    assert repo.tree("HEAD:dir") == merge.tree["dir"]
    assert repo.tree("HEAD^{tree}") == merge.tree
    with pytest.raises(ValueError):
        repo.commit("HEAD^{tree}")
    with pytest.raises(ValueError):
        repo.tree("HEAD:README.md")


def test_rev_parse_rejects_invalid_object_specs(rev_parse_repo):
    repo = rev_parse_repo["repo"]

    with pytest.raises(ValueError):
        repo.rev_parse(":")
    with pytest.raises(ValueError):
        repo.rev_parse(":/")
    with pytest.raises(BadName):
        repo.rev_parse(":/[")
    with pytest.raises(BadName):
        repo.rev_parse("HEAD^{/[}")
    with pytest.raises(ValueError):
        repo.rev_parse(":/!reserved")
    with pytest.raises(ValueError):
        repo.rev_parse("HEAD^{/!reserved}")
    with pytest.raises(ValueError):
        repo.rev_parse("@{-0}")
    with pytest.raises(ValueError):
        repo.rev_parse("HEAD^{invalid}")
    with pytest.raises(BadName):
        repo.rev_parse(":missing")
