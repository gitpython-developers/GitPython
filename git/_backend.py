"""Optional native implementation of library-managed Git operations.

Installing ``GitPython[gix]`` makes the ``gix`` module available. Unsupported
operations return ``NotImplemented`` *before* doing work and use the existing
CLI implementation. Native failures are never retried as CLI mutations.
"""

from collections import Counter
from importlib import import_module
import io
import logging
import os
import re
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


def _canonical_repository(repo: Any) -> Any:
    """Have Gix resolve repository metadata again from a canonical input path."""
    path = os.fspath(repo.git_dir())
    canonical = os.path.realpath(path)
    return gix.open_opts(canonical, repo.open_options()) if path != canonical else repo


def _oid(repo: Any, ref: Any) -> Any:
    ref = safe_decode(ref) if isinstance(ref, bytes) else str(ref)
    if re.fullmatch(r"[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", ref):
        return gix.ObjectId(ref)
    if ref.startswith(":/") or "^{/" in ref or "-dirty" in ref or re.search(r"-\d+-g[0-9a-fA-F]+", ref):
        raise _Unsupported("revision grammar differences (GIX-17)")
    if not hasattr(repo, "rev_parse_single"):
        raise _Unsupported("revision feature disabled")
    return repo.rev_parse_single(ref)


def object_data(command: Any, ref: bytes, *, stream: bool = False) -> Any:
    """Use native object reads without changing the public cat-file interface."""
    if gix is None:
        return NotImplemented
    method = "stream_object_data" if stream else "get_object_header"
    command._require_version()
    try:
        repo = _repository(command, {})
        oid = _oid(repo, ref)
        header = repo.try_find_header(oid)
        if header is None:
            raise ValueError("SHA %s could not be resolved" % oid)
        result: Tuple[Any, ...] = (str(oid), header.kind(), header.size())
        if stream:
            # ponytail: native lookup buffers the object; use CLI above 8 MiB until GIX-2 provides streaming.
            if header.size() > 8 * 1024 * 1024:
                raise _Unsupported("large object streaming (GIX-2)")
            result += (io.BytesIO(repo.find_object(oid).data),)
    except _Unsupported as exc:
        return _fallback(method, str(exc))
    except gix.Error as exc:
        _logger.debug("%s native read: %s", method, exc)
        return _fallback(method, "native read diagnostics")
    record(method, "native")
    return result


def _rev_parse(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if args == ["--path-format=absolute", "--git-common-dir"]:
        return os.fsencode(os.path.abspath(repo.common_dir())) + b"\n"
    if args == ["--is-bare-repository"]:
        return b"true\n" if repo.is_bare() else b"false\n"
    if args == ["--show-object-format"]:
        return str(repo.object_hash()).encode("ascii") + b"\n"
    if args == ["--show-ref-format"]:
        # Config identifies reftable and HEAD reports it as unsupported, but
        # neither validates unknown repository extensions as Git's query does.
        raise _Unsupported("reference storage format query (GIX-1)")
    if args == ["--show-toplevel"] and repo.workdir() is not None:
        return os.fsencode(os.path.abspath(repo.workdir())) + b"\n"
    if args[:1] != ["--verify"] or args[-2:-1] != ["--end-of-options"]:
        raise _Unsupported("discovery or revision options")
    if args[:-2] not in (["--verify"], ["--verify", "--quiet"]):
        raise _Unsupported("revision options")
    return str(_oid(repo, args[-1])).encode("ascii") + b"\n"


def _ls_tree(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if len(args) != 3 or args[:2] != ["-z", "--full-tree"]:
        raise _Unsupported("tree options")
    with repo.find_tree(_oid(repo, args[2])).iter() as entries:
        return b"".join(
            b"%06o %s %s\t%s\0"
            % (
                entry.mode(),
                b"tree" if entry.kind() == "tree" else b"commit" if entry.kind() == "commit" else b"blob",
                str(entry.id()).encode("ascii"),
                entry.filename(),
            )
            for entry in entries
        )


def _symbolic_ref(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if len(args) != 4 or args[:3] != ["--quiet", "--no-recurse", "--"]:
        raise _Unsupported("reference mutation or options")
    reference = repo.try_find_reference(args[-1])
    if reference is None:
        raise _Unsupported("missing reference diagnostics")
    target = reference.target().try_name()
    if target is None:
        raise GitCommandError(["git", "symbolic-ref"], 1)
    return target + b"\n"


def _for_each_ref(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if not args or args[0] != "--format=%(refname)":
        raise _Unsupported("reference format/options")
    split = args.index("--") if "--" in args else len(args)
    if args[1:split] or len(args[split + 1 :]) > 1:
        raise _Unsupported("root refs or reference options")
    prefix = os.fsencode(args[-1]) if len(args) > split + 1 else b""
    if any(char in prefix for char in b"*?["):
        raise _Unsupported("reference glob patterns")
    with repo.references().all() as refs:
        names = [ref.name() for ref in refs]
    return b"".join(
        name + b"\n"
        for name in sorted(names)
        if not prefix or name == prefix or name.startswith(prefix.rstrip(b"/") + b"/")
    )


def _config(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if len(args) == 2 and args[0] == "--get":
        snapshot = repo.config_snapshot()
        value = snapshot.string(args[1])
        if value is None:
            if snapshot.boolean(args[1]) is None:
                raise GitCommandError(["git", "config"], 1)
            value = b""  # An implicit boolean is an empty value in --get output.
        return value + b"\n"
    raise _Unsupported("config file parsing, enumeration, or mutation (GIX-12)")


def _worktree(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if args != ["list", "--porcelain", "-z"] or not hasattr(repo, "worktrees"):
        raise _Unsupported("worktree operation or feature disabled")
    proxies = repo.worktrees()
    if any(proxy.is_prunable() for proxy in proxies):
        raise _Unsupported("prunable worktree diagnostics")
    main = _canonical_repository(repo.main_repo())

    def describe(local: Any) -> List[bytes]:
        workdir = local.workdir()
        fields = [b"worktree " + os.fsencode(workdir or local.git_dir())]
        # Gix's is_bare() reflects configuration, even for a linked worktree.
        if local.is_bare() and workdir is None:
            fields.append(b"bare")
        else:
            head = local.head()
            oid = head.id()
            fields.append(
                b"HEAD " + (str(oid).encode("ascii") if oid is not None else b"0" * local.object_hash().len_in_hex())
            )
            fields.append(b"detached" if head.is_detached() else b"branch " + head.referent_name())
        return fields

    records = [b"\0".join(describe(main)) + b"\0\0"]
    for proxy in sorted(proxies, key=lambda proxy: os.fsencode(proxy.base())):
        fields = describe(proxy.into_repo())
        if proxy.is_locked():
            reason = proxy.lock_reason()
            fields.append(b"locked" + (b" " + reason if reason else b""))
        records.append(b"\0".join(fields) + b"\0\0")
    return b"".join(records)


_HANDLERS: Dict[str, Callable[[Any, List[str], Dict[str, Any]], bytes]] = {
    "rev_parse": _rev_parse,
    "ls_tree": _ls_tree,
    "symbolic_ref": _symbolic_ref,
    "for_each_ref": _for_each_ref,
    "config": _config,
    "worktree": _worktree,
}


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
