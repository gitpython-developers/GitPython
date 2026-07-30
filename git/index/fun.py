# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Standalone functions to accompany the index implementation and make it more
versatile."""

__all__ = [
    "write_cache",
    "read_cache",
    "write_tree_from_cache",
    "entry_key",
    "stat_mode_to_index_mode",
    "S_IFGITLINK",
    "run_commit_hook",
    "hook_path",
]

from io import BytesIO
import os
import os.path as osp
from pathlib import Path
from stat import S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, S_ISDIR, S_ISLNK, S_IXUSR
import subprocess
import sys

from gitdb.base import IStream
from gitdb.typ import str_tree_type

from git.cmd import Git, handle_process_output, safer_popen
from git.compat import defenc, force_bytes, force_text, safe_decode
from git.exc import HookExecutionError, UnmergedEntriesError
from git.objects.fun import (
    traverse_tree_recursive,
    traverse_trees_recursive,
    tree_to_stream,
)
from git.util import IndexFileSHA1Writer, finalize_process

from .typ import CE_EXTENDED, BaseIndexEntry, IndexEntry, CE_NAMEMASK, CE_STAGESHIFT
from .util import pack, unpack

# typing -----------------------------------------------------------------------------

from typing import Dict, IO, List, Sequence, TYPE_CHECKING, Tuple, Type, Union, cast

from git.types import PathLike

if TYPE_CHECKING:
    from git.db import GitCmdObjectDB
    from git.objects.tree import TreeCacheTup

    from .base import IndexFile

# ------------------------------------------------------------------------------------

S_IFGITLINK = S_IFLNK | S_IFDIR
"""Flags for a submodule."""

CE_NAMEMASK_INV = ~CE_NAMEMASK


def hook_path(name: str, git_dir: PathLike) -> str:
    """:return: path to the given named hook in the given git repository directory"""
    return osp.join(git_dir, "hooks", name)


def _commit_hook_path(name: str, index: "IndexFile") -> str:
    """:return: path to the named commit hook, respecting Git's core.hooksPath."""
    with index.repo.config_reader() as config:
        hooks_dir = config.get("core", "hooksPath", fallback="")

    if not hooks_dir:
        return hook_path(name, index.repo.git_dir)

    return osp.abspath(osp.join(index.repo.working_dir, osp.expanduser(hooks_dir), name))


def _has_file_extension(path: str) -> str:
    return osp.splitext(path)[1]


def _is_in_windows_system_root(path: str) -> bool:
    """Return whether ``path`` is inside the Windows installation directory."""
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        return False

    system_root = osp.normcase(osp.realpath(system_root))
    path = osp.normcase(osp.realpath(path))
    try:
        return osp.commonpath((system_root, path)) == system_root
    except ValueError:
        # Paths on different drives have no common path on Windows.
        return False


def _which_from_path(command: str) -> Union[str, None]:
    """Resolve ``command`` from PATH, excluding the Windows installation."""
    for directory in os.get_exec_path():
        # Unlike POSIX, Windows does not define an empty PATH entry as the current
        # directory. Skip it rather than letting abspath() turn it into one.
        if not directory:
            continue
        directory = osp.abspath(directory)
        candidate = osp.join(directory, command)
        # SystemRoot contains the WSL launcher stubs. They are valid executables but
        # not suitable for running a Windows Git hook: the hook path and environment
        # were prepared for Git for Windows, and WSL may have no distribution at all.
        if _is_in_windows_system_root(candidate):
            continue
        if osp.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


_GIT_FOR_WINDOWS_PREFIXES = ("mingw64", "mingw32", "clangarm64", "clang64", "clang32", "ucrt64")


def _git_for_windows_root() -> Union[str, None]:
    """Infer a standard Git for Windows root from GitPython's selected executable."""
    git_executable = os.fspath(Git.GIT_PYTHON_GIT_EXECUTABLE or Git.git_exec_name)
    if osp.dirname(git_executable):
        # CreateProcess resolves a relative executable path containing a directory
        # from the parent process cwd, even when Popen supplies a different child cwd.
        git_executable = osp.abspath(git_executable)
    else:
        # GitPython deliberately retains a bare executable name so later PATH changes
        # affect Git commands. Resolve it with the same PATH snapshot used for Bash.
        names = (git_executable,) if _has_file_extension(git_executable) else (git_executable, f"{git_executable}.exe")
        for name in names:
            resolved = _which_from_path(name)
            if resolved is not None:
                git_executable = resolved
                break
        else:
            git_executable = ""
    if not git_executable:
        return None
    if osp.basename(git_executable).lower() not in ("git", "git.exe"):
        return None

    executable_dir = osp.dirname(git_executable)
    directory_name = osp.basename(executable_dir).lower()
    if directory_name == "cmd":
        # The normal system-wide PATH entry is <git-root>/cmd.
        return osp.dirname(executable_dir)
    if directory_name == "bin":
        prefix = osp.dirname(executable_dir)
        if osp.basename(prefix).lower() in _GIT_FOR_WINDOWS_PREFIXES:
            # Git Bash commonly exposes <git-root>/<platform>/bin/git.exe.
            return osp.dirname(prefix)
        if osp.basename(prefix).lower() != "usr":
            # An explicitly configured Git may be the root-level bin/git.exe. Do
            # not make the same inference from usr/bin: unlike the recognized
            # platform prefixes, "usr" has no reliably bounded parent layout.
            return prefix
    return None


def _git_for_windows_bash() -> Union[str, None]:
    """Return Bash from the Git for Windows installation selected by GitPython."""
    git_root = _git_for_windows_root()
    if git_root is None:
        return None

    # Match gix-path's precedence: prefer the lightweight bin shim, then the
    # underlying usr/bin executable. Both belong to the same installation as Git.
    for relative_path in ("bin/bash.exe", "usr/bin/bash.exe"):
        candidate = osp.join(git_root, *relative_path.split("/"))
        if osp.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def run_commit_hook(name: str, index: "IndexFile", *args: str) -> None:
    """Run the commit hook of the given name. Silently ignore hooks that do not exist.

    :param name:
        Name of hook, like ``pre-commit``.

    :param index:
        :class:`~git.index.base.IndexFile` instance.

    :param args:
        Arguments passed to hook file.

    :raise git.exc.HookExecutionError:
    """
    hp = _commit_hook_path(name, index)
    if not os.access(hp, os.X_OK):
        return

    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = safe_decode(os.fspath(index.path))
    env["GIT_EDITOR"] = ":"
    cmd = [hp]
    try:
        if sys.platform == "win32" and not _has_file_extension(hp):
            # Windows only uses extensions to determine how to open files
            # (doesn't understand shebangs). Try using bash to run the hook.
            try:
                bash_hp = osp.relpath(hp, index.repo.working_dir)
            except ValueError:
                # Different drives have no relative path on Windows. Git Bash accepts
                # an absolute path in this form, although a relative path is preferable
                # because it also works with the Windows Subsystem for Linux wrapper.
                bash_hp = hp
            # Prefer Bash associated with GitPython's selected Git installation. If
            # that layout is not recognized, use an explicitly configured non-system
            # PATH entry. Preserve the bare fallback for installations that previously
            # relied on WSL or another CreateProcess-resolved Bash.
            bash_executable = _git_for_windows_bash() or _which_from_path("bash.exe") or "bash.exe"
            cmd = [bash_executable, Path(bash_hp).as_posix()]

        process = safer_popen(
            cmd + list(args),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=index.repo.working_dir,
        )
    except Exception as ex:
        raise HookExecutionError(hp, ex) from ex
    else:
        stdout_list: List[str] = []
        stderr_list: List[str] = []
        handle_process_output(process, stdout_list.append, stderr_list.append, finalize_process)
        stdout = "".join(stdout_list)
        stderr = "".join(stderr_list)
        if process.returncode != 0:
            stdout = force_text(stdout, defenc)
            stderr = force_text(stderr, defenc)
            raise HookExecutionError(hp, process.returncode, stderr, stdout)
    # END handle return code


def stat_mode_to_index_mode(mode: int) -> int:
    """Convert the given mode from a stat call to the corresponding index mode and
    return it."""
    if S_ISLNK(mode):  # symlinks
        return S_IFLNK
    if S_ISDIR(mode) or S_IFMT(mode) == S_IFGITLINK:  # submodules
        return S_IFGITLINK
    return S_IFREG | (mode & S_IXUSR and 0o755 or 0o644)  # blobs with or without executable bit


def write_cache(
    entries: Sequence[Union[BaseIndexEntry, "IndexEntry"]],
    stream: IO[bytes],
    extension_data: Union[None, bytes] = None,
    ShaStreamCls: Type[IndexFileSHA1Writer] = IndexFileSHA1Writer,
) -> None:
    """Write the cache represented by entries to a stream.

    :param entries:
        **Sorted** list of entries.

    :param stream:
        Stream to wrap into the AdapterStreamCls - it is used for final output.

    :param ShaStreamCls:
        Type to use when writing to the stream. It produces a sha while writing to it,
        before the data is passed on to the wrapped stream.

    :param extension_data:
        Any kind of data to write as a trailer, it must begin a 4 byte identifier,
        followed by its size (4 bytes).
    """
    # Wrap the stream into a compatible writer.
    stream_sha = ShaStreamCls(stream)

    tell = stream_sha.tell
    write = stream_sha.write

    # Header
    version = 3 if any(entry.extended_flags for entry in entries) else 2
    write(b"DIRC")
    write(pack(">LL", version, len(entries)))

    # Body
    for entry in entries:
        beginoffset = tell()
        write(entry.ctime_bytes)  # ctime
        write(entry.mtime_bytes)  # mtime
        path_str = str(entry.path)
        path: bytes = force_bytes(path_str, encoding=defenc)
        plen = len(path) & CE_NAMEMASK  # Path length
        assert plen == len(path), "Path %s too long to fit into index" % entry.path
        flags = plen | (entry.flags & CE_NAMEMASK_INV)  # Clear possible previous values.
        if entry.extended_flags:
            flags |= CE_EXTENDED
        write(
            pack(
                ">LLLLLL20sH",
                entry.dev,
                entry.inode,
                entry.mode,
                entry.uid,
                entry.gid,
                entry.size,
                entry.binsha,
                flags,
            )
        )
        if entry.extended_flags:
            write(pack(">H", entry.extended_flags))
        write(path)
        real_size = (tell() - beginoffset + 8) & ~7
        write(b"\0" * ((beginoffset + real_size) - tell()))
    # END for each entry

    # Write previously cached extensions data.
    if extension_data is not None:
        stream_sha.write(extension_data)

    # Write the sha over the content.
    stream_sha.write_sha()


def read_header(stream: IO[bytes]) -> Tuple[int, int]:
    """Return tuple(version_long, num_entries) from the given stream."""
    type_id = stream.read(4)
    if type_id != b"DIRC":
        raise AssertionError("Invalid index file header: %r" % type_id)
    unpacked = cast(Tuple[int, int], unpack(">LL", stream.read(4 * 2)))
    version, num_entries = unpacked

    assert version in (1, 2, 3), "Unsupported git index version %i, only 1, 2, and 3 are supported" % version
    return version, num_entries


def entry_key(*entry: Union[BaseIndexEntry, PathLike, int]) -> Tuple[PathLike, int]:
    """
    :return:
        Key suitable to be used for the
        :attr:`index.entries <git.index.base.IndexFile.entries>` dictionary.

    :param entry:
        One instance of type BaseIndexEntry or the path and the stage.
    """

    # def is_entry_key_tup(entry_key: Tuple) -> TypeGuard[Tuple[PathLike, int]]:
    #     return isinstance(entry_key, tuple) and len(entry_key) == 2

    if len(entry) == 1:
        entry_first = entry[0]
        assert isinstance(entry_first, BaseIndexEntry)
        return (entry_first.path, entry_first.stage)
    else:
        # assert is_entry_key_tup(entry)
        entry = cast(Tuple[PathLike, int], entry)
        return entry
    # END handle entry


def read_cache(
    stream: IO[bytes],
) -> Tuple[int, Dict[Tuple[PathLike, int], "IndexEntry"], bytes, bytes]:
    """Read a cache file from the given stream.

    :return:
        tuple(version, entries_dict, extension_data, content_sha)

        * *version* is the integer version number.
        * *entries_dict* is a dictionary which maps IndexEntry instances to a path at a
          stage.
        * *extension_data* is ``""`` or 4 bytes of type + 4 bytes of size + size bytes.
        * *content_sha* is a 20 byte sha on all cache file contents.
    """
    version, num_entries = read_header(stream)
    count = 0
    entries: Dict[Tuple[PathLike, int], "IndexEntry"] = {}

    read = stream.read
    tell = stream.tell
    while count < num_entries:
        beginoffset = tell()
        ctime = unpack(">8s", read(8))[0]
        mtime = unpack(">8s", read(8))[0]
        (dev, ino, mode, uid, gid, size, sha, flags) = unpack(">LLLLLL20sH", read(20 + 4 * 6 + 2))
        extended_flags = 0
        if flags & CE_EXTENDED:
            extended_flags = unpack(">H", read(2))[0]
        path_size = flags & CE_NAMEMASK
        path = read(path_size).decode(defenc)

        real_size = (tell() - beginoffset + 8) & ~7
        read((beginoffset + real_size) - tell())
        entry = IndexEntry((mode, sha, flags, path, ctime, mtime, dev, ino, uid, gid, size, extended_flags))
        # entry_key would be the method to use, but we save the effort.
        entries[(path, entry.stage)] = entry
        count += 1
    # END for each entry

    # The footer contains extension data and a sha on the content so far.
    # Keep the extension footer,and verify we have a sha in the end.
    # Extension data format is:
    #   4 bytes ID
    #   4 bytes length of chunk
    #   Repeated 0 - N times
    extension_data = stream.read(~0)
    assert len(extension_data) > 19, (
        "Index Footer was not at least a sha on content as it was only %i bytes in size" % len(extension_data)
    )

    content_sha = extension_data[-20:]

    # Truncate the sha in the end as we will dynamically create it anyway.
    extension_data = extension_data[:-20]

    return (version, entries, extension_data, content_sha)


def write_tree_from_cache(
    entries: List[IndexEntry], odb: "GitCmdObjectDB", sl: slice, si: int = 0
) -> Tuple[bytes, List["TreeCacheTup"]]:
    R"""Create a tree from the given sorted list of entries and put the respective
    trees into the given object database.

    :param entries:
        **Sorted** list of :class:`~git.index.typ.IndexEntry`\s.

    :param odb:
        Object database to store the trees in.

    :param si:
        Start index at which we should start creating subtrees.

    :param sl:
        Slice indicating the range we should process on the entries list.

    :return:
        tuple(binsha, list(tree_entry, ...))

        A tuple of a sha and a list of tree entries being a tuple of hexsha, mode, name.
    """
    tree_items: List["TreeCacheTup"] = []

    ci = sl.start
    end = sl.stop
    while ci < end:
        entry = entries[ci]
        if entry.stage != 0:
            raise UnmergedEntriesError(entry)
        # END abort on unmerged
        ci += 1
        rbound = entry.path.find("/", si)
        if rbound == -1:
            # It's not a tree.
            tree_items.append((entry.binsha, entry.mode, entry.path[si:]))
        else:
            # Find common base range.
            base = entry.path[si:rbound]
            xi = ci
            while xi < end:
                oentry = entries[xi]
                orbound = oentry.path.find("/", si)
                if orbound == -1 or oentry.path[si:orbound] != base:
                    break
                # END abort on base mismatch
                xi += 1
            # END find common base

            # Enter recursion.
            # ci - 1 as we want to count our current item as well.
            sha, _tree_entry_list = write_tree_from_cache(entries, odb, slice(ci - 1, xi), rbound + 1)
            tree_items.append((sha, S_IFDIR, base))

            # Skip ahead.
            ci = xi
        # END handle bounds
    # END for each entry

    # Finally create the tree.
    sio = BytesIO()
    tree_to_stream(tree_items, sio.write)  # Writes to stream as bytes, but doesn't change tree_items.
    sio.seek(0)

    istream = odb.store(IStream(str_tree_type, len(sio.getvalue()), sio))
    return (istream.binsha, tree_items)


def _tree_entry_to_baseindexentry(tree_entry: "TreeCacheTup", stage: int) -> BaseIndexEntry:
    return BaseIndexEntry((tree_entry[1], tree_entry[0], stage << CE_STAGESHIFT, tree_entry[2]))


def aggressive_tree_merge(odb: "GitCmdObjectDB", tree_shas: Sequence[bytes]) -> List[BaseIndexEntry]:
    R"""
    :return:
        List of :class:`~git.index.typ.BaseIndexEntry`\s representing the aggressive
        merge of the given trees. All valid entries are on stage 0, whereas the
        conflicting ones are left on stage 1, 2 or 3, whereas stage 1 corresponds to the
        common ancestor tree, 2 to our tree and 3 to 'their' tree.

    :param tree_shas:
        1, 2 or 3 trees as identified by their binary 20 byte shas. If 1 or two, the
        entries will effectively correspond to the last given tree. If 3 are given, a 3
        way merge is performed.
    """
    out: List[BaseIndexEntry] = []

    # One and two way is the same for us, as we don't have to handle an existing
    # index, instrea
    if len(tree_shas) in (1, 2):
        for entry in traverse_tree_recursive(odb, tree_shas[-1], ""):
            out.append(_tree_entry_to_baseindexentry(entry, 0))
        # END for each entry
        return out
    # END handle single tree

    if len(tree_shas) > 3:
        raise ValueError("Cannot handle %i trees at once" % len(tree_shas))

    # Three trees.
    for base, ours, theirs in traverse_trees_recursive(odb, tree_shas, ""):
        if base is not None:
            # Base version exists.
            if ours is not None:
                # Ours exists.
                if theirs is not None:
                    # It exists in all branches. Ff it was changed in both
                    # its a conflict. Otherwise, we take the changed version.
                    # This should be the most common branch, so it comes first.
                    if (base[0] != ours[0] and base[0] != theirs[0] and ours[0] != theirs[0]) or (
                        base[1] != ours[1] and base[1] != theirs[1] and ours[1] != theirs[1]
                    ):
                        # Changed by both.
                        out.append(_tree_entry_to_baseindexentry(base, 1))
                        out.append(_tree_entry_to_baseindexentry(ours, 2))
                        out.append(_tree_entry_to_baseindexentry(theirs, 3))
                    elif base[0] != ours[0] or base[1] != ours[1]:
                        # Only we changed it.
                        out.append(_tree_entry_to_baseindexentry(ours, 0))
                    else:
                        # Either nobody changed it, or they did. In either
                        # case, use theirs.
                        out.append(_tree_entry_to_baseindexentry(theirs, 0))
                    # END handle modification
                else:
                    if ours[0] != base[0] or ours[1] != base[1]:
                        # They deleted it, we changed it, conflict.
                        out.append(_tree_entry_to_baseindexentry(base, 1))
                        out.append(_tree_entry_to_baseindexentry(ours, 2))
                    # else:
                    #   # We didn't change it, ignore.
                    #   pass
                    # END handle our change
                # END handle theirs
            else:
                if theirs is None:
                    # Deleted in both, its fine - it's out.
                    pass
                else:
                    if theirs[0] != base[0] or theirs[1] != base[1]:
                        # Deleted in ours, changed theirs, conflict.
                        out.append(_tree_entry_to_baseindexentry(base, 1))
                        out.append(_tree_entry_to_baseindexentry(theirs, 3))
                    # END theirs changed
                    # else:
                    #   # Theirs didn't change.
                    #   pass
                # END handle theirs
            # END handle ours
        else:
            # All three can't be None.
            if ours is None:
                # Added in their branch.
                assert theirs is not None
                out.append(_tree_entry_to_baseindexentry(theirs, 0))
            elif theirs is None:
                # Added in our branch.
                out.append(_tree_entry_to_baseindexentry(ours, 0))
            else:
                # Both have it, except for the base, see whether it changed.
                if ours[0] != theirs[0] or ours[1] != theirs[1]:
                    out.append(_tree_entry_to_baseindexentry(ours, 2))
                    out.append(_tree_entry_to_baseindexentry(theirs, 3))
                else:
                    # It was added the same in both.
                    out.append(_tree_entry_to_baseindexentry(ours, 0))
                # END handle two items
            # END handle heads
        # END handle base exists
    # END for each entries tuple

    return out
