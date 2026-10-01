# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Repository and revision queries delegated to Git."""

from __future__ import annotations

__all__ = [
    "rev_parse",
    "is_git_dir",
    "touch",
    "find_submodule_git_dir",
    "name_to_object",
    "short_to_long",
    "deref_tag",
    "to_commit",
    "find_worktree_git_dir",
]

import os
import os.path as osp
import posixpath
import tempfile
from typing import Optional, TYPE_CHECKING, Union, overload

from gitdb.exc import BadName, BadObject

from git.cmd import Git
from git.compat import defenc
from git.exc import GitCommandError
from git.objects import Object
from git.objects.base import IndexObject
from git.refs import SymbolicReference
from git.types import AnyGitObject, Literal, PathLike
from git.util import bin_to_hex, hex_to_bin, to_native_path_linux

if TYPE_CHECKING:
    from gitdb.db import CompoundDB, LooseObjectDB
    from git.objects import Commit
    from .base import Repo


def touch(filename: str) -> str:
    with open(filename, "ab"):
        pass
    return filename


def find_submodule_git_dir(d: PathLike) -> Optional[PathLike]:
    """Resolve a repository directory or gitfile using Git."""
    path = osp.abspath(os.fspath(d))
    if not osp.exists(path):
        return None
    try:
        return Git()._call_process_safe("rev_parse", "--resolve-git-dir", to_native_path_linux(path))
    except GitCommandError:
        return None


def is_git_dir(d: PathLike) -> bool:
    """Whether Git recognizes the directory as repository storage."""
    return osp.isdir(d) and find_submodule_git_dir(d) is not None


def find_worktree_git_dir(dotgit: PathLike) -> Optional[str]:
    """Resolve an existing worktree gitfile without parsing its contents."""
    if not osp.isfile(dotgit):
        return None
    result = find_submodule_git_dir(dotgit)
    return os.fspath(result) if result is not None else None


def short_to_long(odb: Union["CompoundDB", "LooseObjectDB"], hexsha: str) -> Optional[bytes]:
    """Resolve an abbreviated object ID using the selected object database."""
    try:
        return bin_to_hex(odb.partial_to_complete_sha_hex(hexsha))
    except BadObject:
        return None


@overload
def name_to_object(repo: "Repo", name: str, return_ref: Literal[False] = ...) -> AnyGitObject: ...


@overload
def name_to_object(repo: "Repo", name: str, return_ref: Literal[True]) -> Union[AnyGitObject, SymbolicReference]: ...


def name_to_object(repo: "Repo", name: str, return_ref: bool = False) -> Union[AnyGitObject, SymbolicReference]:
    """Resolve a revision, optionally returning its fully qualified reference."""
    name = Git._check_operand(name, "revision")
    if not return_ref:
        return rev_parse(repo, name)
    try:
        path = repo.git._call_process_safe(
            "rev_parse", "--symbolic-full-name", "--verify", "--quiet", "--end-of-options", name
        )
    except GitCommandError as exc:
        if exc.status != 1:
            raise
        raise BadObject(name) from exc
    if not path:
        raise BadObject(name)
    SymbolicReference._check_ref_name_valid(path)
    return SymbolicReference.from_path(repo, path)


def deref_tag(tag: AnyGitObject) -> AnyGitObject:
    """Return the object obtained by peeling tags through Git."""
    return rev_parse(tag.repo, tag.hexsha + "^{}") if tag.type == "tag" else tag


def to_commit(obj: AnyGitObject) -> "Commit":
    """Convert an object or annotated tag to a commit."""
    obj = deref_tag(obj)
    if obj.type != "commit":
        raise ValueError("Cannot convert object %r to type commit" % obj)
    return obj


def rev_parse(repo: "Repo", rev: str) -> AnyGitObject:
    """Resolve a Git revision to an object using Git's native revision grammar.

    Invalid or missing revisions raise :class:`gitdb.exc.BadName`. Option-like
    revisions and embedded command delimiters are rejected before invoking Git.
    """
    rev = Git._check_operand(rev, "revision")
    try:
        oid = repo.git._call_process_safe("rev_parse", "--verify", "--quiet", "--end-of-options", rev)
    except GitCommandError as exc:
        if exc.status != 1 and "Invalid regular expression" not in exc.stderr:
            raise
        raise BadName(rev) from exc
    if not repo.re_hexsha_only.fullmatch(oid):
        raise BadName(rev)
    obj = Object.new_from_sha(repo, hex_to_bin(oid))
    if isinstance(obj, IndexObject) and ":" in rev:
        # Git resolves the mode, including index stages and executable/symlink
        # entries. No object storage or revision grammar is decoded in Python.
        with tempfile.TemporaryFile() as stream:
            stream.write(rev.encode(defenc, "surrogateescape") + b"\0")
            stream.seek(0)
            mode = repo.git._call_process_safe("cat_file", "--batch-check=%(objectmode)", "-Z", istream=stream).strip(
                "\0"
            )
        if mode:
            obj.mode = int(mode, 8)
            if rev.startswith(":"):
                # The only remaining blob/tree context is an index entry.
                path = rev[3:] if len(rev) > 2 and rev[1] in "0123" and rev[2] == ":" else rev[1:]
                obj.path = posixpath.normpath(path) if path else ""
            else:
                # Git has no path format atom. Ask it which colon follows a
                # tree-ish; earlier colons can belong to commit-message regexes.
                for index, char in enumerate(rev):
                    if char != ":":
                        continue
                    try:
                        repo.git._call_process_safe(
                            "rev_parse", "--verify", "--quiet", "--end-of-options", rev[:index] + "^{tree}"
                        )
                    except GitCommandError as exc:
                        if exc.status != 1:
                            raise
                        continue
                    path = rev[index + 1 :]
                    obj.path = posixpath.normpath(path) if path else ""
                    break
    return obj
