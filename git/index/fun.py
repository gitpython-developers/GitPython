# This module is part of GitPython and is released under the 3-Clause BSD License.
"""Index helpers; Git owns index formats and merge algorithms."""

import os
from stat import S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, S_ISDIR, S_ISLNK, S_IXUSR
from typing import TYPE_CHECKING, Tuple, Union, cast

from git.cmd import Git
from git.exc import GitCommandError, HookExecutionError, UnsafeOptionError
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
    """Run a Git commit hook, ignoring missing hooks.

    :raise GitCommandError: If Git rejects the repository before executing its hook.
    """
    Git._check_operand(name, "hook name")
    if name not in ("pre-commit", "commit-msg", "post-commit"):
        raise ValueError("Only commit hooks are supported")
    if any("\0" in arg for arg in Git._unpack_args(args)):
        raise UnsafeOptionError("Git arguments cannot contain NUL bytes")
    command = index.repo.git
    # Repo's automatic GIT_DIR bypasses Git's discovery-time ownership check.
    one_shot_options, command._git_options = command._git_options, ()
    options = [*command._persistent_git_options, *one_shot_options]
    discovery_env = {}
    if (
        "GIT_DIR" in command._repository_environment
        and command.environment().get("GIT_DIR") == command._repository_environment["GIT_DIR"]
        and not any(option == "-C" or option == "--git-dir" or option.startswith("--git-dir=") for option in options)
    ):
        options[:0] = ["-C", index.repo._discovery_path]
        discovery_env = {
            key: None
            for key, value in command._repository_environment.items()
            if command.environment().get(key) == value
        }
    command.execute(
        [command.GIT_PYTHON_GIT_EXECUTABLE, *options, "rev-parse", "--git-dir"],
        env=discovery_env,
        _repository_redirected="-C" in options,
    )
    command._git_options = one_shot_options
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
