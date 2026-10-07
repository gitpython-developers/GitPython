"""Optional native implementation of library-managed Git operations.

Installing ``GitPython[gix]`` makes the ``gix`` module available. Unsupported
operations return ``NotImplemented`` before mutation and use the existing CLI
implementation. Native mutation failures are never retried through the CLI.
"""

from collections import Counter
from glob import glob
from importlib import import_module
import io
from itertools import islice
import logging
import os
import re
import stat
from threading import Lock
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, cast

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


def discover_repository(path: str, environment: Dict[str, Any]) -> Any:
    """Open one discovery candidate; the caller controls parent traversal."""
    if gix is None:
        return NotImplemented
    effective = {**os.environ, **environment}
    if any(
        effective.get(key)
        for key in ("GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE")
    ) or any(value != os.environ.get(key) for key, value in environment.items() if key != "GIT_WORK_TREE"):
        return _fallback("Repo.open", "storage or command environment")
    options = gix.OpenOptions().open_path_as_is(True).bail_if_untrusted(True).strict_config(True)
    options = options.config_overrides(
        ["core.fsmonitor=false", "gc.auto=0", "maintenance.auto=false", "core.hooksPath=" + os.devnull]
    )
    try:
        repo = gix.open_opts(path, options)
        snapshot = repo.config_snapshot()
        if snapshot.string("extensions.refStorage") == b"reftable":
            return _fallback("Repo.open", "reftable (GIX-1)")
        if snapshot.string("extensions.compatObjectFormat") is not None:
            return _fallback("Repo.open", "compatibility object format (GIX-19)")
        # Discovery accepts undecodable HEADs; force the native reference decoder.
        repo.head()
        if not repo.is_bare() and repo.workdir() is None and not effective.get("GIT_WORK_TREE"):
            return _fallback("Repo.open", "missing native worktree metadata (GIX-14)")
        commondir = os.path.join(repo.git_dir(), "commondir")
        if os.path.lexists(commondir):
            # Gix ignores invalid commondir files on common repositories. A common
            # directory must have been resolved and contain actual shared storage.
            if os.path.realpath(repo.common_dir()) == os.path.realpath(repo.git_dir()) or not all(
                os.path.isdir(os.path.join(repo.common_dir(), entry)) for entry in ("objects", "refs")
            ):
                return _fallback("Repo.open", "common-directory validation (GIX-14)")
        record("Repo.open", "native")
        return repo
    except gix.Error as exc:
        # Retain Git's rejection/diagnostics for layouts Gix cannot open yet.
        _logger.debug("native discovery: %s", exc)
        return _fallback("Repo.open", "native discovery diagnostics")


def _repository(command: Any, env: Dict[str, Any], *, query_config: bool = False) -> Any:
    owner = command._repo() if command._repo is not None else None
    if owner is not None:
        with owner._gix_lock:
            return _open_repository(command, env, query_config=query_config)
    return _open_repository(command, env, query_config=query_config)


def _open_repository(command: Any, env: Dict[str, Any], *, query_config: bool = False) -> Any:
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
    owner = command._repo() if command._repo is not None else None
    state = None
    repo = None
    if owner is not None and not query_config:
        # Gix refreshes index/ODB snapshots itself; configuration is loaded at open.
        paths = [
            path,
            os.fspath(owner.common_dir),
            os.path.join(owner.common_dir, "config"),
            os.path.join(path, "config.worktree"),
        ]
        paths += [
            effective.get("GIT_CONFIG_SYSTEM", "/etc/gitconfig"),
            effective.get("GIT_CONFIG_GLOBAL", os.path.expanduser("~/.gitconfig")),
            os.path.join(effective.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "git", "config"),
            os.path.join(owner.common_dir, "objects", "info", "alternates"),
            os.path.join(path, "commondir"),
            os.path.join(path, "gitdir"),
        ]
        stamps: List[Any] = []
        for filename in paths:
            try:
                info = os.stat(filename)
                stamps.append((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
            except FileNotFoundError:
                stamps.append(None)
        state = (path, tuple(sorted(effective.items())), tuple(stamps))
        repo = owner._gix_repository
        if repo is not None and os.path.realpath(repo.git_dir()) != os.path.realpath(path):
            repo = None
        if repo is not None and state != owner._gix_state:
            repo.reload()
    if repo is None:
        repo = gix.open_opts(path, options)
    snapshot = repo.config_snapshot()
    if snapshot.string("extensions.refStorage") == b"reftable":
        raise _Unsupported("reftable (GIX-1)")
    if snapshot.string("extensions.compatObjectFormat") is not None:
        raise _Unsupported("compatibility object format (GIX-19)")
    if effective.get("GIT_WORK_TREE") and (owner is None or query_config or state != owner._gix_state):
        workdir = effective["GIT_WORK_TREE"]
        if not os.path.isabs(workdir):
            workdir = os.path.join(command.working_dir or os.getcwd(), workdir)
        repo.set_workdir(workdir)
    if owner is not None and not query_config:
        owner._gix_repository = repo
        # ponytail: includes can load arbitrary files; reopen until Gix exposes their source paths.
        if state != owner._gix_state:
            included = re.search(rb"\[include(?:if)?[\s\]]", repo.config_snapshot().plumbing().to_bstring(), re.I)
            owner._gix_state = None if included else state
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
        return b"true\n" if repo.is_bare() and repo.workdir() is None else b"false\n"
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
        names = []
        for ref in refs:
            names.append(ref.name())
            if ref.target().try_name() is not None:
                # Git omits dangling symbolic refs; defer their diagnostics to it.
                ref.follow_to_object()
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


def _worktree_root(command: Any, repo: Any) -> str:
    root = repo.workdir()
    if (
        root is None
        or repo.prefix() is not None
        or os.path.realpath(command.working_dir or os.getcwd()) != os.path.realpath(root)
    ):
        raise _Unsupported("worktree or command working directory")
    return os.fspath(root)


def is_dirty(command: Any, index: bool, working_tree: bool, untracked: bool, submodules: bool, path: Any) -> Any:
    if gix is None:
        return NotImplemented
    method = "Repo.is_dirty"
    try:
        repo = _repository(command, {})
        _worktree_root(command, repo)
        if not hasattr(repo, "status"):
            raise _Unsupported("status feature disabled")
        patterns = [os.fspath(path)] if path else []
        if any("\0" in pattern for pattern in patterns):
            raise _Unsupported("invalid pathspec")
        status = (
            repo.status()
            .index(_index(repo, {"env": command.environment()}))
            .untracked_files("files" if untracked else "none")
            .tree_index_track_renames(None)
            .index_worktree_rewrites(None)
            .index_worktree_submodules("configured" if submodules else "all", check_dirty=submodules)
        )
        dirty = False
        with status.into_iter(patterns) as entries:
            for item in entries:
                if item.summary() is None:
                    continue
                if item.kind == "TreeIndex":
                    if index and (submodules or item.details["entry_mode"] != 0o160000):
                        dirty = True
                        break
                elif item.details["kind"] == "DirectoryContents":
                    if untracked and item.details["entry"]["status"] == "Untracked":
                        dirty = True
                        break
                elif working_tree:
                    dirty = True
                    break
    except _Unsupported as exc:
        return _fallback(method, str(exc))
    except gix.Error as exc:
        _logger.debug("is_dirty native read: %s", exc)
        return _fallback(method, "native read diagnostics")
    record(method, "native")
    return dirty


def untracked_files(command: Any, args: Tuple[Any, ...], options: Dict[str, Any]) -> Any:
    if gix is None:
        return NotImplemented
    method = "Repo.untracked_files"
    try:
        if options.keys() - {"ignore_submodules"}:
            raise _Unsupported("status options")
        repo = _repository(command, {})
        _worktree_root(command, repo)
        if not hasattr(repo, "dirwalk_iter"):
            raise _Unsupported("dirwalk feature disabled")
        index = _index(repo, {"env": command.environment()})
        patterns = command._unpack_args([arg for arg in args if arg is not None])
        if any("\0" in path for path in patterns):
            raise _Unsupported("invalid pathspec")
        walk_options = repo.dirwalk_options().emit_untracked("matching").emit_tracked(False)
        result = []
        with repo.dirwalk_iter(index, patterns, walk_options) as entries:
            for item in entries:
                entry = item.entry
                if entry.status == "Untracked":
                    path = entry.rela_path
                    if entry.disk_kind in ("Directory", "Repository"):
                        path += b"/"
                    result.append(path)
        result.sort()
    except _Unsupported as exc:
        return _fallback(method, str(exc))
    except gix.Error as exc:
        _logger.debug("untracked_files native read: %s", exc)
        return _fallback(method, "native read diagnostics")
    record(method, "native")
    return [safe_decode(path) for path in result]


def ignored(command: Any, paths: Sequence[Any]) -> Any:
    if gix is None:
        return NotImplemented
    method = "Repo.ignored"
    try:
        repo = _repository(command, {})
        root = _worktree_root(command, repo)
        if not hasattr(repo, "excludes"):
            raise _Unsupported("excludes feature disabled")
        index = _index(repo, {"env": command.environment()})
        excludes = repo.excludes(index)
        with index.entries() as entries:
            tracked = {entry.path() for entry in entries}
        result = []
        for path in paths:
            path = os.fspath(path)
            relative = os.path.relpath(path, root) if os.path.isabs(path) else path
            relative = relative.replace(os.sep, "/")
            if any(part in (".", "..", ".git") for part in relative.split("/")) or relative.startswith(":"):
                raise _Unsupported("ignore path normalization")
            # check-ignore rejects traversal through symlinks and tracked gitlinks.
            parent = relative.rstrip("/")
            while "/" in parent:
                parent = parent.rsplit("/", 1)[0]
                if os.path.islink(os.path.join(root, parent)) or os.fsencode(parent) in tracked:
                    raise _Unsupported("ignore path traverses symlink or submodule")
            if os.fsencode(relative.rstrip("/")) in tracked:
                continue
            mode: Optional[int]
            try:
                mode = os.lstat(os.path.join(root, relative)).st_mode
            except FileNotFoundError:
                mode = stat.S_IFDIR if relative.endswith("/") else None
            else:
                mode = 0o40000 if stat.S_ISDIR(mode) else 0o120000 if stat.S_ISLNK(mode) else 0o100644
            if excludes.at_entry(os.fsencode(relative), mode).is_excluded():
                result.append(path)
    except _Unsupported as exc:
        return _fallback(method, str(exc))
    except gix.Error as exc:
        _logger.debug("ignored native read: %s", exc)
        return _fallback(method, "native read diagnostics")
    record(method, "native")
    return result


def _merge_base(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if not hasattr(repo, "merge_base"):
        raise _Unsupported("revision feature disabled")
    ancestor = args[:1] == ["--is-ancestor"]
    if ancestor:
        args = args[1:]
    if len(args) != 3 or args[0] != "--":
        raise _Unsupported("merge-base options")
    one, two = (_oid(repo, value) for value in args[1:])
    if kwargs.get("all"):
        ids = repo.merge_bases_many(one, [two])
    else:
        base = repo.merge_base(one, two)
        ids = [base] if base is not None else []
    if not ids or (ancestor and ids[0] != one):
        raise GitCommandError(["git", "merge-base"], 1)
    return b"" if ancestor else b"".join(str(oid).encode("ascii") + b"\n" for oid in ids)


def _walk(repo: Any, rev: str, options: Dict[str, Any]) -> Iterator[str]:
    if not hasattr(repo, "rev_walk"):
        raise _Unsupported("revision feature disabled")
    if options.keys() - {"max_count", "skip", "first_parent"}:
        raise _Unsupported("history options or ordering (GIX-8)")
    if options.get("first_parent") not in (None, True, False):
        raise _Unsupported("history options")
    start, count = options.get("skip", 0), options.get("max_count")
    if type(start) is not int or start < 0 or (count is not None and (type(count) is not int or count < 0)):
        raise _Unsupported("history limits")
    tip = repo.find_object(_oid(repo, rev)).peel_to_commit().id
    platform = repo.rev_walk([tip])
    if options.get("first_parent"):
        platform = platform.first_parent_only()
    cursor = platform.all()

    def iterate() -> Iterator[str]:
        try:
            with cursor:
                for item in islice(cursor, start, None if count is None else start + count):
                    yield str(item.id)
        except gix.Error as exc:
            raise GitCommandError(["gix", "rev-list", rev], 128, str(exc)) from exc

    return iterate()


def history(command: Any, rev: str, paths: Any, options: Dict[str, Any], *, count: bool = False) -> Any:
    """Count reachable commits, or lazily walk the first-parent chain."""
    if gix is None:
        return NotImplemented
    method = "Commit.count" if count else "Commit.iter_items"
    try:
        if paths:
            raise _Unsupported("history path filtering")
        if (
            not count
            and not options.get("first_parent")
            and not (options.get("max_count") == 1 and not options.get("skip"))
        ):
            raise _Unsupported("Git history ordering (GIX-8)")
        iterator = _walk(_repository(command, {}), rev, options)
        result = sum(1 for _ in iterator) if count else iterator
    except _Unsupported as exc:
        return _fallback(method, str(exc))
    except gix.Error as exc:
        _logger.debug("%s native preparation: %s", method, exc)
        return _fallback(method, "native preparation diagnostics")
    record(method, "native")
    return result


def _date(signature: Any) -> bytes:
    offset = signature.time.offset
    hours, minutes = divmod(abs(offset) // 60, 60)
    return b"%d %s%02d%02d" % (signature.time.seconds, b"-" if offset < 0 else b"+", hours, minutes)


def _reflog(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if len(args) == 3 and args[:2] == ["exists", "--"]:
        reference = repo.try_find_reference(args[-1])
        if reference is None:
            raise _Unsupported("orphan reflog lookup")
        if not reference.log_exists():
            raise GitCommandError(["git", "reflog", "exists"], 1)
        return b""
    if (
        len(args) != 10
        or args[:8]
        != [
            "show",
            "--format=%H%x00%gn%x00%ge%x00%gD%x00%gs",
            "--date=raw",
            "-z",
            "--no-abbrev",
            "--no-decorate",
            "--no-notes",
            "--no-color",
        ]
        or args[-1] != "--"
    ):
        raise _Unsupported("reflog writing or format")
    reference = repo.try_find_reference(args[-2])
    if reference is None:
        raise _Unsupported("orphan reflog lookup")
    cursor = reference.log_iter().rev()
    if cursor is None:
        return b""
    output = []
    with cursor:
        for line in cursor:
            if not repo.has_object(line.new_oid) or repo.find_header(line.new_oid).kind() != "commit":
                continue
            signature = line.signature
            output.append(
                b"\0".join(
                    [
                        str(line.new_oid).encode("ascii"),
                        signature.name,
                        signature.email,
                        os.fsencode(args[-2]) + b"@{" + _date(signature) + b"}",
                        line.message,
                    ]
                )
                + b"\0"
            )
    return b"".join(output)


def _index(repo: Any, kwargs: Dict[str, Any]) -> Any:
    if not hasattr(repo, "index_or_empty"):
        raise _Unsupported("index feature disabled")
    path = kwargs.get("env", {}).get("GIT_INDEX_FILE", os.environ.get("GIT_INDEX_FILE"))
    if path and not os.path.isabs(path):
        raise _Unsupported("relative index path")
    if path and os.path.abspath(path) != os.path.abspath(repo.index_path()):
        raise _Unsupported("custom index path (GIX-3)")
    index = repo.index_or_empty()
    if index.is_sparse():
        raise _Unsupported("sparse index (GIX-4)")
    return index


def _ls_files(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if args != ["--stage", "-v", "-z", "--full-name"]:
        raise _Unsupported("index listing options")
    with _index(repo, kwargs).entries() as entries:
        output = []
        for entry in entries:
            flag = b"S" if entry.flags & (1 << 30) else b"M" if entry.stage() else b"H"
            if entry.flags & (1 << 15):
                flag = flag.lower()
            output.append(
                b"%s %06o %s %d\t%s\0" % (flag, entry.mode, str(entry.id).encode("ascii"), entry.stage(), entry.path())
            )
    return b"".join(output)


def _update_index(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if args != ["--show-index-version"]:
        raise _Unsupported("index mutation options")
    return str(_index(repo, kwargs).version()).encode("ascii") + b"\n"


def _index_from_tree(repo: Any, tree: Any) -> Any:
    if not hasattr(repo, "index_from_tree"):
        raise _Unsupported("index feature disabled")
    if (
        repo.config_snapshot().integer("index.version") not in (None, 2)
        or os.environ.get("GIT_INDEX_VERSION", "2") != "2"
    ):
        raise _Unsupported("new index version selection (GIX-13)")
    return repo.index_from_tree(tree)


def materialize_index(command: Any, source: Any, destination: str, desired: Dict[Any, Any], dirty: Any) -> Any:
    """Write a private index, retaining native metadata for unchanged entries."""
    if gix is None:
        return NotImplemented
    method = "IndexFile.write"
    try:
        if any(stage for _path, stage in desired):
            raise _Unsupported("unmerged index editing")
        if any(not entry.binsha.strip(b"\0") for entry in desired.values()):
            raise _Unsupported("null index object IDs")
        names = {os.fsencode(path) for path, _stage in desired}
        for path in names:
            while b"/" in path:
                path = path.rsplit(b"/", 1)[0]
                if path in names:
                    raise _Unsupported("overlapping index paths")
        repo = _repository(command, {})
        if os.path.exists(source):
            if repo.config_snapshot().boolean("core.splitIndex") or glob(
                os.path.join(os.path.dirname(os.fspath(source)), "sharedindex.*")
            ):
                raise _Unsupported("split index preservation (GIX-13)")
            index = _index(repo, {"env": {"GIT_INDEX_FILE": os.fspath(source)}})
            if index.version() != 2:
                raise _Unsupported("index version preservation (GIX-13)")
        else:
            index = _index_from_tree(repo, repo.empty_tree())
        # Keep path-independent flags that GitPython exposes; changed paths get fresh stat data.
        mask = (3 << 12) | (1 << 15) | (1 << 30)
        changed = {os.fsencode(path) for path in dirty}
        with index.entries() as entries:
            current = list(entries)
        for entry in current:
            wanted = desired.get((safe_decode(entry.path()), entry.stage()))
            if wanted is None or (entry.mode, str(entry.id), entry.flags & mask) != (
                wanted.mode,
                wanted.hexsha,
                wanted.flags & mask,
            ):
                changed.add(entry.path())
        changed.update(names - {entry.path() for entry in current})
        # ponytail: per-entry removals shift a vector; use a bulk binding for very large edits.
        for position, entry in reversed(list(enumerate(current))):
            if entry.path() in changed:
                index.remove_entry_at_index(position)
        for (path, _stage), entry in desired.items():
            if os.fsencode(path) in changed:
                index.dangerously_push_entry(
                    gix.IndexStat(), gix.ObjectId(entry.hexsha), entry.flags & mask, entry.mode, os.fsencode(path)
                )
        index.sort_entries()
        index.verify_entries()
        index.set_path(destination)
        _write("index", index.write)
    except _Unsupported as exc:
        return _fallback(method, str(exc))
    except gix.Error as exc:
        _logger.debug("materialize_index native preparation: %s", exc)
        return _fallback(method, "native preparation diagnostics")
    record(method, "native")
    return None


def _write(method: str, function: Callable[[], Any]) -> Any:
    """Once a write starts, an error must not cause a second attempt through Git."""
    try:
        return function()
    except gix.Error as exc:
        raise GitCommandError(["gix", method], 128, str(exc)) from exc


def _input(kwargs: Dict[str, Any]) -> bytes:
    stream = kwargs.get("istream")
    if stream is None or not hasattr(stream, "seekable") or not stream.seekable():
        raise _Unsupported("nonseekable input")
    start = stream.tell()
    try:
        stream.seek(0, 2)
        if stream.tell() - start > 8 * 1024 * 1024:
            raise _Unsupported("large object streaming (GIX-2)")
        stream.seek(start)
        data = stream.read()
    finally:
        stream.seek(start)
    if not isinstance(data, bytes):
        raise _Unsupported("nonbinary input")
    return data


def _hash_object(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if len(args) not in (3, 4) or args[0] != "-t" or args[-1] != "--stdin":
        raise _Unsupported("object hashing options")
    write = args[2:-1] == ["-w"]
    if args[2:-1] not in ([], ["-w"]):
        raise _Unsupported("object hashing options")
    kind = args[1]
    if kind not in ("blob", "tree", "commit", "tag"):
        raise _Unsupported("object kind")
    data = _input(kwargs)
    # Validate and check the encoded bytes in memory before touching object storage.
    memory = repo.with_object_memory()
    oid = memory.write_object(kind, data)
    if memory.find_object(oid).data != data:
        raise _Unsupported("object serialization changes bytes (GIX-5)")
    if write:
        oid = _write("hash_object", lambda: repo.write_object(kind, data))
    kwargs["istream"].seek(len(data), 1)
    return str(oid).encode("ascii") + b"\n"


_ENTRY_KINDS = {0o100644: "blob", 0o100755: "exe", 0o120000: "link", 0o160000: "commit", 0o40000: "tree"}


def _write_tree(repo: Any, entries: Sequence[Tuple[bytes, int, str]]) -> str:
    names = {name for name, _mode, _oid in entries}
    if len(names) != len(entries):
        raise _Unsupported("duplicate or overlapping tree paths")
    for name in names:
        while b"/" in name:
            name = name.rsplit(b"/", 1)[0]
            if name in names:
                raise _Unsupported("duplicate or overlapping tree paths")
    for _path, mode, oid in entries:
        object_id = gix.ObjectId(oid)
        if object_id.is_null():
            raise _Unsupported("null tree object IDs")
        header = repo.try_find_header(object_id)
        if header is None:
            if mode != 0o160000:
                raise _Unsupported("missing tree children (GIX-7)")
        elif header.kind() != ("tree" if mode == 0o40000 else "commit" if mode == 0o160000 else "blob"):
            raise _Unsupported("tree child object kind")
    with repo.empty_tree().edit() as editor:
        for path, mode, oid in entries:
            editor.upsert(path, _ENTRY_KINDS[mode], gix.ObjectId(oid))
        return str(_write("write_tree", editor.write))


def write_tree(command: Any, entries: Sequence[Tuple[bytes, int, str]]) -> Any:
    if gix is None:
        return NotImplemented
    try:
        result = _write_tree(_repository(command, {}), entries)
    except _Unsupported as exc:
        return _fallback("IndexFile.write_tree", str(exc))
    except gix.Error as exc:
        _logger.debug("write_tree native preparation: %s", exc)
        return _fallback("IndexFile.write_tree", "native preparation diagnostics")
    record("IndexFile.write_tree", "native")
    return result


def tree_diff(repository: Any, left: Any, right: Any, paths: Any, patch: bool, options: Dict[str, Any]) -> Any:
    """Build GitPython's raw tree diff directly from native change records."""
    if gix is None:
        return NotImplemented
    from git.diff import Diff, DiffIndex, Lit_change_type

    method = "Diffable.diff"
    try:
        if not hasattr(left, "hexsha") or not (hasattr(right, "hexsha") or isinstance(right, str)):
            raise _Unsupported("index/worktree/root diff")
        if patch or paths:
            raise _Unsupported("patch formatting or path filtering")
        if options.keys() - {"R", "no_renames"} or any(type(value) is not bool for value in options.values()):
            raise _Unsupported("diff options")
        if "no_renames" in options and not options["no_renames"]:
            raise _Unsupported("configured rename detection")
        repo = _repository(repository.git, {})
        if not hasattr(repo, "diff_tree_to_tree"):
            raise _Unsupported("tree-diff feature disabled")
        before = repo.find_object(_oid(repo, left.hexsha)).peel_to_tree()
        after = repo.find_object(_oid(repo, getattr(right, "hexsha", right))).peel_to_tree()
        if options.get("R"):
            before, after = after, before
        diff_options = gix.DiffOptions().track_path().track_rewrites(None)
        changes = repo.diff_tree_to_tree(before, after, diff_options)
        if not options.get("no_renames"):
            added = [str(c.id()) for c in changes if c.kind == "Addition" and c.entry_mode() != 0o40000]
            deleted = [str(c.id()) for c in changes if c.kind == "Deletion" and c.entry_mode() != 0o40000]
            if added and deleted:
                if (set(added) - set(deleted) and set(deleted) - set(added)) or (
                    len(set(added)) != len(added) or len(set(deleted)) != len(deleted)
                ):
                    raise _Unsupported("inexact or ambiguous rename detection (GIX-11)")
                # Exact rewrites need no blob filters, textconv, or external diff drivers.
                diff_options = diff_options.track_rewrites(gix.Rewrites(percentage=None))
                changes = repo.diff_tree_to_tree(before, after, diff_options)
        result: DiffIndex[Diff] = DiffIndex()
        for change in changes:
            details = change.details
            kind, path, mode, oid = change.kind, change.location(), change.entry_mode(), str(change.id())
            previous_mode = details.get("previous_entry_mode", details.get("source_entry_mode", mode))
            previous_oid = str(details.get("previous_id", details.get("source_id", change.id())))
            if mode == 0o40000 or previous_mode == 0o40000:
                if mode != previous_mode:
                    raise _Unsupported("directory type change")
                continue
            new_file, deleted_file, renamed = kind == "Addition", kind == "Deletion", kind == "Rewrite"
            change_type = (
                "A"
                if new_file
                else "D"
                if deleted_file
                else "R"
                if renamed
                else ("T" if mode & 0o170000 != previous_mode & 0o170000 else "M")
            )
            source = change.source_location() if renamed else path
            result.append(
                Diff(
                    repository,
                    source,
                    path,
                    None if new_file else previous_oid,
                    None if deleted_file else oid,
                    "%06o" % (0 if new_file else previous_mode),
                    "%06o" % (0 if deleted_file else mode),
                    new_file,
                    deleted_file,
                    False,
                    source if renamed else None,
                    path if renamed else None,
                    "",
                    cast(Lit_change_type, change_type),
                    100 if renamed else None,
                )
            )
        result.sort(key=lambda diff: diff.b_rawpath or b"")
    except _Unsupported as exc:
        return _fallback(method, str(exc))
    except gix.Error as exc:
        _logger.debug("tree_diff native read: %s", exc)
        return _fallback(method, "native read diagnostics")
    record(method, "native")
    return result


def commit_stats(commit: Any) -> Any:
    """Count changed lines natively, retaining Git's statistics representation."""
    if gix is None:
        return NotImplemented
    from git.util import Stats

    method = "Commit.stats"
    try:
        repo = _repository(commit.repo.git, {})
        if not hasattr(repo, "diff_tree_to_tree") or not hasattr(repo, "attributes_only"):
            raise _Unsupported("diff or attributes feature disabled")
        if repo.config_snapshot().string("diff.algorithm") not in (None, b"myers", b"default"):
            raise _Unsupported("statistics diff algorithm")
        native = repo.find_commit(gix.ObjectId(commit.hexsha))
        with native.parent_ids() as parents:
            parent = next(parents, None)
        before = repo.empty_tree() if parent is None else repo.find_commit(parent).tree()
        changes = repo.diff_tree_to_tree(before, native.tree(), gix.DiffOptions().track_path().track_rewrites(None))
        index = _index(repo, {"env": commit.repo.git.environment()})
        # The blob cache reads index attributes, whereas Git also reads worktree attributes.
        attributes = [repo.attributes_only(index, source) for source in ("id_mapping", "worktree_then_id_mapping")]
        cache = repo.diff_resource_cache_for_tree_diff()
        lines = []
        for change in sorted(changes, key=lambda change: change.location()):
            mode = change.entry_mode()
            previous_mode = change.details.get("previous_entry_mode", mode)
            if mode == 0o40000 or previous_mode == 0o40000:
                if mode != previous_mode:
                    raise _Unsupported("statistics directory type change")
                continue
            if mode == 0o160000 or previous_mode == 0o160000:
                raise _Unsupported("statistics gitlinks")
            path = change.location()
            if any(byte < 32 or byte >= 127 or byte in b'"\\' for byte in path):
                raise _Unsupported("statistics filename quoting")
            for stack in attributes:
                outcome = stack.selected_attribute_matches(["diff"])
                stack.at_entry(path, mode).matching_attributes(outcome)
                with outcome.iter_selected() as matches:
                    if any(match.state != "unspecified" for match in matches):
                        raise _Unsupported("statistics diff attributes (GIX-18)")
            for oid in (change.id(), change.details.get("previous_id")):
                if oid is not None and repo.find_header(oid).size() > 8 * 1024 * 1024:
                    raise _Unsupported("large object streaming (GIX-2)")
            counts = change.diff(cache).line_counts()
            cache.clear_resource_cache()
            kind = {"Addition": "A", "Deletion": "D", "Modification": "M"}[change.kind]
            if mode & 0o170000 != previous_mode & 0o170000:
                kind = "T"
            lines.append(
                "%s\t%d\t%d\t%s\n"
                % (kind, counts.insertions if counts else 0, counts.removals if counts else 0, safe_decode(path))
            )
        result = Stats._list_from_string(commit.repo, "".join(lines))
    except _Unsupported as exc:
        return _fallback(method, str(exc))
    except gix.Error as exc:
        _logger.debug("commit_stats native read: %s", exc)
        return _fallback(method, "native read diagnostics")
    record(method, "native")
    return result


def _mktree(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if args != ["-z", "--missing"]:
        raise _Unsupported("tree writing options")
    data = _input(kwargs)
    entries = []
    for record in data.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode_bytes, kind, oid_bytes = metadata.split()
        mode = int(mode_bytes, 8)
        if mode not in _ENTRY_KINDS or b"/" in path or path in (b"", b".", b"..", b".git"):
            raise _Unsupported("tree entry")
        expected = b"tree" if mode == 0o40000 else b"commit" if mode == 0o160000 else b"blob"
        if kind != expected:
            raise _Unsupported("tree entry kind")
        entries.append((path, mode, oid_bytes.decode("ascii")))
    oid = _write_tree(repo, entries)
    kwargs["istream"].seek(len(data), 1)
    return oid.encode("ascii") + b"\n"


def _read_tree(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if len(args) != 1 or (args[0] != "--empty" and args[0].startswith("-")):
        raise _Unsupported("index merge options")
    path = kwargs.get("env", {}).get("GIT_INDEX_FILE")
    if not path or os.path.exists(path):
        raise _Unsupported("existing index metadata")
    tree = repo.empty_tree() if args == ["--empty"] else repo.find_object(_oid(repo, args[0])).peel_to_tree()
    index = _index_from_tree(repo, tree)
    index.set_path(path)
    _write("read_tree", index.write)
    return b""


def _checked_signature(signature: Any) -> Any:
    # Git strips "crud" at the edges and angle brackets/newlines within identities.
    crud = bytes(range(33)) + b".,:;<>\"'\\"
    for value in (signature.name, signature.email):
        if not value or value != value.strip(crud) or any(char in value for char in b"<>\r\n\0"):
            raise _Unsupported("identity normalization")
    return signature


def _signature(env: Dict[str, Any], role: str) -> Any:
    prefix = "GIT_" + role + "_"
    name, email, date = (env.get(prefix + field) for field in ("NAME", "EMAIL", "DATE"))
    match = re.fullmatch(r"(-?\d+) ([+-])(\d\d)(\d\d)", date or "")
    if not name or not email or match is None:
        raise _Unsupported("identity resolution")
    seconds, sign, hours, minutes = match.groups()
    offset = (int(hours) * 60 + int(minutes)) * 60 * (-1 if sign == "-" else 1)
    return _checked_signature(gix.Signature(name, email, int(seconds), offset))


def _committer(repo: Any, env: Dict[str, Any]) -> Any:
    for field in ("NAME", "EMAIL", "DATE"):
        key = "GIT_COMMITTER_" + field
        if key in env and env[key] != os.environ.get(key):
            raise _Unsupported("per-command committer identity (GIX-21)")
        if os.environ.get(key) == "":
            raise _Unsupported("empty identity")
    signature = repo.committer()
    if signature is None:
        raise _Unsupported("identity resolution")
    return _checked_signature(signature)


def _var(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if args != ["GIT_COMMITTER_IDENT"]:
        raise _Unsupported("Git variable")
    signature = _committer(repo, kwargs.get("env", {}))
    return signature.name + b" <" + signature.email + b"> " + _date(signature) + b"\n"


def _update_ref(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if "--" not in args:
        raise _Unsupported("reference transactions (GIX-9)")
    split = args.index("--")
    options, operands = args[:split], args[split + 1 :]
    deref, force_log, delete, message = True, False, False, ""
    cursor = iter(options)
    for option in cursor:
        if option == "--no-deref":
            deref = False
        elif option == "--create-reflog":
            force_log = True
        elif option == "-d":
            delete = True
        elif option == "-m":
            message = next(cursor, "")
        else:
            raise _Unsupported("reference options")
    # LogChange sets each edit's message, but its writer does not normalize it.
    if re.search(r"[\t\r\n\v\f]|^ | $| {2}", message):
        raise _Unsupported("reflog message cleanup (GIX-10)")
    if delete:
        if len(operands) != 1 or deref:
            raise _Unsupported("reference deletion options")
        edit = gix.RefEdit.delete(operands[0], gix.PreviousValue.Any).with_deref(False)
        _write("update_ref", lambda: repo.edit_references_as([edit]))
        return b""
    if len(operands) != 2:
        raise _Unsupported("strict reference creation / compare-and-swap (GIX-9)")
    name, target = operands
    oid = _oid(repo, target)
    kind = repo.find_header(oid).kind()
    if (name == "HEAD" or name.startswith("refs/heads/")) and kind != "commit":
        raise _Unsupported("branch target validation")
    reference = repo.try_find_reference(name)
    if reference is not None:
        if deref and name != "HEAD" and reference.target().try_name() is not None:
            raise _Unsupported("symbolic reference update (GIX-10)")
        if not deref and reference.target().try_name() is not None:
            raise _Unsupported("detaching symbolic ref reflog (GIX-10)")
        if reference.follow_to_object() == oid:
            raise _Unsupported("unchanged reference reflog (GIX-10)")
    head = repo.try_find_reference("HEAD")
    for _ in range(5):
        if head is None or head.target().try_name() is None:
            break
        if head.target().try_name() == os.fsencode(name):
            raise _Unsupported("active branch HEAD reflog (GIX-10)")
        head = head.follow()
    log = gix.LogChange()
    log.force_create_reflog = force_log
    log.message = message
    edit = gix.RefEdit.update_with_log(name, gix.Target.Object(oid), gix.PreviousValue.Any, log).with_deref(deref)
    signature = _committer(repo, kwargs.get("env", {}))
    _write("update_ref", lambda: repo.edit_references_as([edit], signature))
    return b""


def _commit_tree(repo: Any, args: List[str], kwargs: Dict[str, Any]) -> bytes:
    if len(args) < 2 or args[0] != "--no-gpg-sign" or args[2::2] != ["-p"] * len(args[2::2]):
        raise _Unsupported("commit options")
    if len(args) % 2 or any(setting.lower() != "i18n.commitencoding=utf-8" for setting in kwargs.get("_config", ())):
        raise _Unsupported("commit encoding (GIX-6)")
    data = _input(kwargs)
    try:
        message = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _Unsupported("commit message bytes (GIX-6)") from None
    parents = args[3::2]
    if len(set(parents)) != len(parents):
        raise _Unsupported("duplicate parents")
    author = _signature(kwargs.get("env", {}), "AUTHOR")
    committer = _signature(kwargs.get("env", {}), "COMMITTER")
    tree = _oid(repo, args[1])
    # Native commit creation accepts literal IDs, whereas commit-tree verifies kinds.
    if repo.find_header(tree).kind() != "tree" or any(
        repo.find_header(_oid(repo, p)).kind() != "commit" for p in parents
    ):
        raise _Unsupported("commit object kinds")
    commit = _write("commit_tree", lambda: repo.new_commit_as(committer, author, message, tree, parents))
    kwargs["istream"].seek(len(data), 1)
    return str(commit.id).encode("ascii") + b"\n"


_HANDLERS: Dict[str, Callable[[Any, List[str], Dict[str, Any]], bytes]] = {
    "rev_parse": _rev_parse,
    "ls_tree": _ls_tree,
    "symbolic_ref": _symbolic_ref,
    "for_each_ref": _for_each_ref,
    "merge_base": _merge_base,
    "ls_files": _ls_files,
    "update_index": _update_index,
    "hash_object": _hash_object,
    "mktree": _mktree,
    "read_tree": _read_tree,
    "commit_tree": _commit_tree,
    "reflog": _reflog,
    "var": _var,
    "update_ref": _update_ref,
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
