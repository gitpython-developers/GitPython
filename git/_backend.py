"""Optional native implementation of library-managed Git operations.

Installing ``GitPython[gix]`` makes the ``gix`` module available. Unsupported
operations return ``NotImplemented`` *before* doing work and use the existing
CLI implementation. Native failures are never retried as CLI mutations.
"""

from collections import Counter
from importlib import import_module
import logging
import os
from threading import Lock
from typing import Any, Callable, Dict, List, Sequence, Tuple

from git.compat import safe_decode
from git.exc import GitCommandError

try:
    gix: Any = import_module("gix")
except ModuleNotFoundError as exc:
    if exc.name != "gix":
        raise
    gix = None

name = "gix" if gix is not None else "cli"
_counts: Counter = Counter()
_lock = Lock()
_logger = logging.getLogger("git.backend")


def record(method: str, outcome: str) -> None:
    with _lock:
        _counts[method, outcome] += 1
    _logger.debug("%s: %s", method, outcome)


def statistics() -> Dict[Tuple[str, str], int]:
    """Return counts by operation and native/fallback reason for this process."""
    with _lock:
        return dict(_counts)


class _Unsupported(Exception):
    """A capability decision made before a native mutation."""


def _fallback(method: str, reason: str) -> Any:
    record(method, "CLI: " + reason)
    return NotImplemented


def _repository(command: Any, env: Dict[str, Any], *, query_config: bool = False) -> Any:
    if command._git_options or command._persistent_git_options:
        raise _Unsupported("global command options")
    overrides = {**command.environment(), **env}
    effective = {**os.environ, **overrides}
    path = overrides.get("GIT_DIR")
    if not path:
        raise _Unsupported("repository not bound")
    if not os.path.isabs(path):
        path = os.path.join(command.working_dir or os.getcwd(), path)
    for key in ("GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE"):
        if effective.get(key):
            raise _Unsupported("storage environment")
    supported = {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"}
    supported.update(
        "GIT_%s_%s" % (role, field) for role in ("AUTHOR", "COMMITTER") for field in ("NAME", "EMAIL", "DATE")
    )
    if any(key not in supported and value != os.environ.get(key) for key, value in overrides.items()):
        raise _Unsupported("command environment")
    options = gix.OpenOptions().open_path_as_is(True).bail_if_untrusted(True).strict_config(True)
    if not query_config:
        options = options.config_overrides(
            ["core.fsmonitor=false", "gc.auto=0", "maintenance.auto=false", "core.hooksPath=" + os.devnull]
        )
    repo = gix.open_opts(path, options)
    if repo.config_snapshot().string("extensions.refStorage") == b"reftable":
        raise _Unsupported("reftable (GIX-1)")
    if effective.get("GIT_WORK_TREE"):
        workdir = effective["GIT_WORK_TREE"]
        if not os.path.isabs(workdir):
            workdir = os.path.join(command.working_dir or os.getcwd(), workdir)
        repo.set_workdir(workdir)
    return repo


_HANDLERS: Dict[str, Callable[[Any, List[str], Dict[str, Any]], bytes]] = {}


def dispatch(
    command: Any, method: str, args: Tuple[Any, ...], kwargs: Dict[str, Any], config: Sequence[str] = ()
) -> Any:
    if gix is None:
        return NotImplemented
    handler = _HANDLERS.get(method)
    if handler is None:
        return _fallback(method, "not converted")
    allowed = {"env", "stdout_as_string", "strip_newline_in_stdout", "with_extended_output"}
    if method == "merge_base":
        allowed.add("all")
    if method in ("hash_object", "mktree", "commit_tree"):
        allowed.add("istream")
    if kwargs.keys() - allowed:
        return _fallback(method, "command/process options")
    if config and method != "commit_tree":
        return _fallback(method, "configuration overrides")
    if config:
        kwargs = dict(kwargs, _config=config)
    kwargs = dict(kwargs, env={**command.environment(), **(kwargs.get("env") or {})})
    try:
        args_list = command._unpack_args([arg for arg in args if arg is not None])
        repo = _repository(command, kwargs.get("env", {}), query_config=method == "config")
        output = handler(repo, args_list, kwargs)
    except _Unsupported as exc:
        return _fallback(method, str(exc))
    except GitCommandError:
        record(method, "native")
        raise
    except gix.Error as exc:
        _logger.debug("%s native read: %s", method, exc)
        return _fallback(method, "native read diagnostics")
    record(method, "native")
    if kwargs.get("strip_newline_in_stdout", True) and output.endswith(b"\n"):
        output = output[:-1]
    result = safe_decode(output) if kwargs.get("stdout_as_string", True) else output
    return (0, result, "") if kwargs.get("with_extended_output") else result
