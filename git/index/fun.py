# This module is part of GitPython and is released under the 3-Clause BSD License.
"""Index helpers; Git owns index formats and merge algorithms."""

import os
from stat import S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, S_ISDIR, S_ISLNK, S_IXUSR
from typing import TYPE_CHECKING, Tuple, Union, cast

from git.cmd import Git
from git.exc import GitCommandError, HookExecutionError
from git.types import PathLike
from .typ import BaseIndexEntry

if TYPE_CHECKING:
    from .base import IndexFile

__all__ = ["entry_key", "stat_mode_to_index_mode", "S_IFGITLINK", "run_commit_hook", "hook_path"]

S_IFGITLINK = S_IFLNK | S_IFDIR


def hook_path(name: str, git_dir: PathLike) -> str:
    """Return the conventional hook path; Git handles configured hook paths."""
    Git._check_operand(name, "hook name")
    if "/" in name or "\\" in name:
        raise ValueError("Invalid hook name")
    return os.path.join(git_dir, "hooks", name)


def run_commit_hook(name: str, index: "IndexFile", *args: str) -> None:
    """Run a native Git hook, ignoring missing hooks."""
    Git._check_operand(name, "hook name")
    if name not in ("pre-commit", "commit-msg", "post-commit"):
        raise ValueError("Only native commit hooks are supported")
    try:
        index.repo.git._call_process_safe(
            "hook",
            "run",
            "--ignore-missing",
            name,
            "--",
            *args,
            _allow_hooks=True,
            env={"GIT_INDEX_FILE": os.path.abspath(index.path), "GIT_EDITOR": ":"},
        )
    except GitCommandError as error:
        raise HookExecutionError(error.command, error.status, error.stderr, error.stdout) from error


def stat_mode_to_index_mode(mode: int) -> int:
    """Convert a filesystem mode to a Git index mode."""
    if S_ISLNK(mode):
        return S_IFLNK
    if S_ISDIR(mode) or S_IFMT(mode) == S_IFGITLINK:
        return S_IFGITLINK
    return S_IFREG | (0o755 if mode & S_IXUSR else 0o644)


def entry_key(*entry: Union[BaseIndexEntry, PathLike, int]) -> Tuple[PathLike, int]:
    """Return the path/stage key of an entry, or a supplied path and stage."""
    if len(entry) == 1 and isinstance(entry[0], BaseIndexEntry):
        return entry[0].path, entry[0].stage
    if len(entry) == 2:
        return cast(PathLike, entry[0]), cast(int, entry[1])
    raise TypeError("Expected an index entry or a path and stage")
