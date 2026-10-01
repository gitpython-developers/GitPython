# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Module containing :class:`IndexFile`, an Index implementation facilitating all kinds
of index manipulations such as querying and merging."""

__all__ = ["IndexFile", "CheckoutError", "StageType"]

import contextlib
import datetime
import glob
from io import BytesIO
import os
import os.path as osp
from stat import S_ISLNK, S_ISREG
import subprocess
import shutil
import tempfile

from gitdb.base import IStream

from git import _backend
from git.compat import defenc, force_bytes, safe_decode
from git.cmd import Git
import git.diff as git_diff
from git.exc import CheckoutError, GitCommandError, GitError, InvalidGitRepositoryError, UnmergedEntriesError
from git.objects import Blob, Commit, Object, Submodule, Tree
from git.util import (
    Actor,
    LazyMixin,
    LockedFD,
    join_path_native,
    _is_path_rooted,
    _to_relative_path,
    _validate_repo_path,
    to_native_path_linux,
    unbare_repo,
)

from .fun import (
    S_IFGITLINK,
    entry_key,
    run_commit_hook,
    stat_mode_to_index_mode,
)
from .typ import BaseIndexEntry, IndexEntry, StageType, CE_STAGESHIFT, CE_VALID, CE_EXT_SKIP_WORKTREE
from .util import post_clear_cache, default_index, git_working_dir

# typing -----------------------------------------------------------------------------

from typing import (
    Any,
    BinaryIO,
    Callable,
    cast,
    Dict,
    Generator,
    Iterable,
    Iterator,
    List,
    NoReturn,
    Sequence,
    Set,
    TYPE_CHECKING,
    Tuple,
    Union,
)

from git.types import Literal, PathLike

if TYPE_CHECKING:
    from subprocess import Popen

    from git.refs.reference import Reference
    from git.repo import Repo


Treeish = Union[Tree, Commit, str, bytes, Sequence[Union[Tree, Commit, str, bytes]]]

# ------------------------------------------------------------------------------------


class IndexFile(LazyMixin, git_diff.Diffable):
    """An index whose storage and merge operations are implemented by Git.

    This provides merging facilities allowing to merge without actually changing
    your index or your working tree. This way you can perform your own test merges based
    on the index only without having to deal with the working copy. This is useful in
    case of partial working trees.

    Entries:

        The index contains an entries dict whose keys are tuples of type
        :class:`~git.index.typ.IndexEntry` to facilitate access.

        You may read the entries dict or manipulate it using IndexEntry instance, i.e.::

            index.entries[index.entry_key(index_entry_instance)] = index_entry_instance

    Make sure you use :meth:`index.write() <write>` once you are done manipulating the
    index directly before operating on it using the git command.
    """

    unsafe_git_checkout_index_options = ["--prefix"]
    unsafe_git_read_tree_options = ["--index-output"]

    __slots__ = ("repo", "entries", "_file_path", "_dirty_paths")

    S_IFGITLINK = S_IFGITLINK
    """Flags for a submodule."""

    def __init__(self, repo: "Repo", file_path: Union[PathLike, None] = None) -> None:
        """Initialize this Index instance, optionally from the given `file_path`.

        If no `file_path` is given, we will be created from the current index file.

        If a stream is not given, the stream will be initialized from the current
        repository's index on demand.
        """
        self.repo = repo
        self._dirty_paths: Set[str] = set()
        self._file_path: PathLike = file_path or self._index_path()

    def _set_cache_(self, attr: str) -> None:
        if attr == "entries":
            self.entries = self._read_entries(self.path)
        else:
            super()._set_cache_(attr)

    def _read_entries(self, path: PathLike) -> Dict[Tuple[PathLike, StageType], IndexEntry]:
        output = self.repo.git._call_process_safe(
            "ls_files",
            "--stage",
            "-v",
            "-z",
            "--full-name",
            env={"GIT_INDEX_FILE": osp.abspath(path)},
            stdout_as_string=False,
        )
        entries: Dict[Tuple[PathLike, StageType], IndexEntry] = {}
        for record in output.split(b"\0"):
            if not record:
                continue
            metadata, path_bytes = record.split(b"\t", 1)
            tag, mode, oid, stage = metadata.split()
            entry_path = safe_decode(path_bytes)
            _validate_repo_path(entry_path)
            binsha = bytes.fromhex(oid.decode("ascii"))
            if len(binsha) != self.repo._oid_size or int(stage) not in range(4):
                raise ValueError("Invalid index entry returned by Git")
            flags = int(stage) << CE_STAGESHIFT
            if tag.islower():
                flags |= CE_VALID
            if tag.upper() == b"S":
                flags |= CE_EXT_SKIP_WORKTREE << 16
            entry = IndexEntry((int(mode, 8), binsha, flags, entry_path))
            entries[(entry_path, entry.stage)] = entry
        return entries

    @property
    def version(self) -> int:
        """The index version reported by Git, or 2 for a not-yet-written index."""
        if not osp.exists(self.path):
            return 2
        return int(
            self.repo.git._call_process_safe(
                "update_index", "--show-index-version", env={"GIT_INDEX_FILE": osp.abspath(self.path)}
            )
        )

    def _validated_entries(self) -> Dict[Tuple[PathLike, StageType], IndexEntry]:
        """Validate the complete update before either backend can write."""
        desired: Dict[Tuple[PathLike, StageType], IndexEntry] = {}
        for key, entry in self.entries.items():
            path = os.fspath(entry.path)
            _validate_repo_path(path)
            if key != (entry.path, entry.stage):
                raise ValueError("Index key must match the entry path and stage")
            if len(entry.binsha) != self.repo._oid_size or entry.mode not in (0o100644, 0o100755, 0o120000, 0o160000):
                raise ValueError("Invalid index object ID or mode")
            desired[(path, entry.stage)] = entry
        return desired

    @contextlib.contextmanager
    def _materialized_index(self) -> Generator[str, None, None]:
        """Apply the in-memory entries to a private, Git-managed index."""
        desired = self._validated_entries()
        with tempfile.TemporaryDirectory(prefix="gitpython-index-") as directory:
            path = osp.join(directory, "index")
            native = _backend.materialize_index(self.repo.git, self.path, path, desired, self._dirty_paths)
            if native is not NotImplemented:
                yield path
                return
            env = {"GIT_INDEX_FILE": path}
            if osp.isfile(self.path):
                shutil.copyfile(self.path, path)
            else:
                self.repo.git._call_process_safe("read_tree", "--empty", env=env)
            current = self._read_entries(path)
            changed = set(self._dirty_paths)
            for key in current.keys() | desired.keys():
                if current.get(key) != desired.get(key):
                    changed.add(os.fspath(key[0]))
            if changed:
                # A zero-mode record clears all conflict stages for this path.
                records = []
                for name in sorted(changed):
                    _validate_repo_path(name)
                    name_bytes = name.encode(defenc, "surrogateescape")
                    records.append(b"0 " + self.repo._null_hexsha.encode("ascii") + b"\t" + name_bytes + b"\0")
                    for stage in range(4):
                        desired_entry = desired.get((name, stage))
                        if desired_entry is not None:
                            records.append(
                                ("%o %s %d\t" % (desired_entry.mode, desired_entry.hexsha, stage)).encode("ascii")
                                + name_bytes
                                + b"\0"
                            )
                with tempfile.TemporaryFile() as stream:
                    stream.write(b"".join(records))
                    stream.seek(0)
                    self.repo.git._call_process_safe("update_index", "-z", "--index-info", istream=stream, env=env)
                # Git can report success while ignoring names unsupported on this
                # platform. Do not publish an index with silently missing entries.
                actual = self._read_entries(path)
                if actual.keys() != desired.keys() or any(actual[key][:2] != desired[key][:2] for key in actual):
                    raise ValueError("Git did not retain the requested index entries; filenames may be unsupported")
                for option, mask in (("--assume-unchanged", CE_VALID), ("--skip-worktree", CE_EXT_SKIP_WORKTREE << 16)):
                    names = [
                        name.encode(defenc, "surrogateescape") + b"\0"
                        for name in sorted(changed)
                        if (name, 0) in desired and desired[(name, 0)].flags & mask
                    ]
                    if names:
                        with tempfile.TemporaryFile() as stream:
                            stream.write(b"".join(names))
                            stream.seek(0)
                            self.repo.git._call_process_safe(
                                "update_index", option, "-z", "--stdin", istream=stream, env=env
                            )
            yield path

    def _tree_oid(self, tree: Treeish) -> str:
        # The documented merge workflow passes the singleton result of merge_base().
        if isinstance(tree, (list, tuple)):
            if len(tree) != 1:
                raise ValueError("A tree revision sequence must contain exactly one revision")
            tree = tree[0]
        if isinstance(tree, bytes):
            tree = tree.hex() if len(tree) == self.repo._oid_size else tree.decode("ascii")
        value = str(tree)
        Git._check_operand(value, "tree revision")
        return self.repo.git._call_process_safe("rev_parse", "--verify", "--end-of-options", value + "^{tree}")

    def _index_path(self) -> PathLike:
        if self.repo.git_dir:
            return join_path_native(self.repo.git_dir, "index")
        else:
            raise GitCommandError("No git directory given to join index path")

    @property
    def path(self) -> PathLike:
        """:return: Path to the index file we are representing"""
        return self._file_path

    def _delete_entries_cache(self) -> None:
        """Safely clear the entries cache so it can be recreated."""
        try:
            del self.entries
        except AttributeError:
            # It failed in Python 2.6.5 with AttributeError.
            # FIXME: Look into whether we can just remove this except clause now.
            pass
        # END exception handling

    def _entries_sorted(self) -> List[IndexEntry]:
        return sorted(self.entries.values(), key=lambda e: (e.path, e.stage))

    def write(self, file_path: Union[None, PathLike] = None, ignore_extension_data: bool = False) -> None:
        """Write semantic entries atomically. Git manages index extensions itself.

        ``ignore_extension_data`` is retained for compatibility and has no effect;
        Git invalidates its own caches when entries change.
        """
        self.entries  # noqa: B018 - Load before acquiring the destination lock.
        target = file_path or self.path
        lock = LockedFD(target)
        stream = lock.open(write=True, stream=True)
        try:
            assert not isinstance(stream, int)
            with self._materialized_index() as path, open(path, "rb") as source:
                shutil.copyfileobj(source, stream)
            lock.commit()
        except BaseException:
            lock.rollback()
            raise
        self._file_path = target
        self._dirty_paths.clear()

    @post_clear_cache
    @default_index
    def merge_tree(
        self,
        rhs: Treeish,
        base: Union[None, Treeish] = None,
        allow_unsafe_options: bool = False,
    ) -> "IndexFile":
        """Merge the given `rhs` treeish into the current index, possibly taking
        a common base treeish into account.

        As opposed to the :func:`from_tree` method, this allows you to use an already
        existing tree as the left side of the merge.

        :param rhs:
            Treeish reference pointing to the 'other' side of the merge.

        :param base:
            Optional treeish reference pointing to the common base of `rhs` and this
            index which equals lhs.

        :param allow_unsafe_options:
            Allow options that may write to arbitrary paths.

        :return:
            self (containing the merge and possibly unmerged entries in case of
            conflicts)

        :raise git.exc.GitCommandError:
            If there is a merge conflict. The error will be raised at the first
            conflicting path. If you want to have proper merge resolution to be done by
            yourself, you have to commit the changed index (or make a valid tree from
            it) and retry with a three-way :meth:`index.from_tree <from_tree>` call.
        """
        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([base, rhs]),
                unsafe_options=self.unsafe_git_read_tree_options,
            )

        # -i : ignore working tree status
        # --aggressive : handle more merge cases
        # -m : do an actual merge
        args: List[Union[Treeish, str]] = ["--aggressive", "-i", "-m"]
        if base is not None:
            args.append(self._tree_oid(base))
        args.append(self._tree_oid(rhs))

        self.repo.git._call_process_safe("read_tree", args)
        return self

    @classmethod
    def new(cls, repo: "Repo", *tree_sha: Union[str, bytes, Tree]) -> "IndexFile":
        """Merge the given treeish revisions into a new index which is returned.

        This method behaves like ``git-read-tree --aggressive`` when doing the merge.

        :param repo:
            The repository treeish are located in.

        :param tree_sha:
            Binary or hexadecimal tree object IDs in the repository's object format,
            or tree objects.

        :return:
            New :class:`IndexFile` instance. Its path will be undefined.
            If you intend to write such a merged Index, supply an alternate
            ``file_path`` to its :meth:`write` method.
        """
        if not 1 <= len(tree_sha) <= 3:
            raise ValueError("Specify between one and three trees")
        return cls.from_tree(repo, *(tree_sha[-1:] if len(tree_sha) < 3 else tree_sha))

    @classmethod
    def from_tree(
        cls,
        repo: "Repo",
        *treeish: Treeish,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> "IndexFile":
        R"""Merge the given treeish revisions into a new index which is returned.
        The original index will remain unaltered.

        :param repo:
            The repository treeish are located in.

        :param treeish:
            One, two or three :class:`~git.objects.tree.Tree` objects,
            :class:`~git.objects.commit.Commit`\s or hexadecimal object IDs in the
            repository's object format.

            The result changes according to the amount of trees:

            1. If 1 Tree is given, it will just be read into a new index.
            2. If 2 Trees are given, they will be merged into a new index using a two
               way merge algorithm. Tree 1 is the 'current' tree, tree 2 is the 'other'
               one. It behaves like a fast-forward.
            3. If 3 Trees are given, a 3-way merge will be performed with the first tree
               being the common ancestor of tree 2 and tree 3. Tree 2 is the 'current'
               tree, tree 3 is the 'other' one.

        :param kwargs:
            Additional arguments passed to :manpage:`git-read-tree(1)`.

        :param allow_unsafe_options:
            Allow options that may write to arbitrary paths.

        :return:
            New :class:`IndexFile` instance. It will point to a temporary index location
            which does not exist anymore. If you intend to write such a merged Index,
            supply an alternate ``file_path`` to its :meth:`write` method.

        :note:
            In the three-way merge case, ``--aggressive`` will be specified to
            automatically resolve more cases in a commonly correct manner. Specify
            ``trivial=True`` as a keyword argument to override that.

            Git uses a private index; the repository index and working tree are unchanged.
        """
        if len(treeish) == 0 or len(treeish) > 3:
            raise ValueError("Please specify between 1 and 3 treeish, got %i" % len(treeish))

        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates(treeish, kwargs),
                unsafe_options=cls.unsafe_git_read_tree_options,
            )

        if set(kwargs) - {"trivial", "aggressive", "verbose"}:
            raise ValueError("Unsupported read-tree options")
        with tempfile.TemporaryDirectory(prefix="gitpython-merge-") as directory:
            path = osp.join(directory, "index")
            index = cls(repo, path)
            args = [index._tree_oid(tree) for tree in treeish]
            if len(args) > 1:
                args[:0] = ["--reset", "--aggressive", "-i"]
            repo.git._call_process_safe("read_tree", *args, env={"GIT_INDEX_FILE": path}, **kwargs)
            index.entries  # noqa: B018 - Cache before deleting the temporary index.
            return index

    # UTILITIES

    @unbare_repo
    def _iter_expand_paths(self: "IndexFile", paths: Sequence[PathLike]) -> Iterator[PathLike]:
        """Expand the directories in list of paths to the corresponding paths
        accordingly.

        :note:
            git will add items multiple times even if a glob overlapped with manually
            specified paths or if paths where specified multiple times - we respect that
            and do not prune.
        """

        def raise_exc(e: Exception) -> NoReturn:
            raise e

        r = str(self.repo.working_tree_dir)
        rs = r + os.sep
        for path in paths:
            abs_path = os.fspath(path)
            if not osp.isabs(abs_path):
                abs_path = osp.join(r, path)
            # END make absolute path

            try:
                st = os.lstat(abs_path)  # Handles non-symlinks as well.
            except OSError:
                # The lstat call may fail as the path may contain globs as well.
                pass
            else:
                if S_ISLNK(st.st_mode):
                    yield abs_path.replace(rs, "")
                    continue
            # END check symlink

            # If the path is not already pointing to an existing file, resolve globs if possible.
            if not os.path.exists(abs_path) and ("?" in abs_path or "*" in abs_path or "[" in abs_path):
                resolved_paths = glob.glob(abs_path)
                # not abs_path in resolved_paths:
                #   A glob() resolving to the same path we are feeding it with is a
                #   glob() that failed to resolve. If we continued calling ourselves
                #   we'd endlessly recurse. If the condition below evaluates to true
                #   then we are likely dealing with a file whose name contains wildcard
                #   characters.
                if abs_path not in resolved_paths:
                    for f in self._iter_expand_paths(glob.glob(abs_path)):
                        yield str(f).replace(rs, "")
                    continue
            # END glob handling
            try:
                for root, dirs, files in os.walk(abs_path, onerror=raise_exc):
                    for dirname in dirs[:]:
                        directory = osp.join(root, dirname)
                        try:
                            _validate_repo_path(to_native_path_linux(osp.relpath(directory, r)))
                        except ValueError:
                            dirs.remove(dirname)
                            continue
                        if osp.islink(directory):
                            dirs.remove(dirname)
                            yield osp.relpath(directory, r)
                    for rela_file in files:
                        # Add relative paths only.
                        yield osp.join(root.replace(rs, ""), rela_file)
                    # END for each file in subdir
                # END for each subdirectory
            except OSError:
                # It was a file or something that could not be iterated.
                yield abs_path.replace(rs, "")
            # END path exception handling
        # END for each path

    def _write_path_to_stdin(
        self,
        proc: "Popen",
        filepath: PathLike,
        item: PathLike,
        fmakeexc: Callable[..., GitError],
        fprogress: Callable[[PathLike, bool, PathLike], None],
        read_from_stdout: bool = True,
    ) -> Union[None, str]:
        """Write path to ``proc.stdin`` and make sure it processes the item, including
        progress.

        :return:
            stdout string

        :param read_from_stdout:
            If ``True``, ``proc.stdout`` will be read after the item was sent to stdin.
            In that case, it will return ``None``.

        :note:
            There is a bug in :manpage:`git-update-index(1)` that prevents it from
            sending reports just in time. This is why we have a version that tries to
            read stdout and one which doesn't. In fact, the stdout is not important as
            the piped-in files are processed anyway and just in time.

        :note:
            Newlines are essential here, git's behaviour is somewhat inconsistent on
            this depending on the version, hence we try our best to deal with newlines
            carefully. Usually the last newline will not be sent, instead we will close
            stdin to break the pipe.
        """
        fprogress(filepath, False, item)
        rval: Union[None, str] = None

        if proc.stdin is not None:
            try:
                proc.stdin.write(os.fspath(filepath).encode(defenc, "surrogateescape") + b"\0")
            except OSError as e:
                # Pipe broke, usually because some error happened.
                raise fmakeexc() from e
            # END write exception handling
            proc.stdin.flush()

        if read_from_stdout and proc.stdout is not None:
            rval = proc.stdout.readline().strip()
        fprogress(filepath, True, item)
        return rval

    def iter_blobs(
        self, predicate: Callable[[Tuple[StageType, Blob]], bool] = lambda t: True
    ) -> Iterator[Tuple[StageType, Blob]]:
        """
        :return:
            Iterator yielding tuples of :class:`~git.objects.blob.Blob` objects and
            stages, tuple(stage, Blob).

        :param predicate:
            Function(t) returning ``True`` if tuple(stage, Blob) should be yielded by
            the iterator. A default filter, the :class:`~git.index.typ.BlobFilter`, allows you
            to yield blobs only if they match a given list of paths.
        """
        for entry in self.entries.values():
            blob = entry.to_blob(self.repo)
            output = (entry.stage, blob)
            if predicate(output):
                yield output
        # END for each entry

    def unmerged_blobs(self) -> Dict[PathLike, List[Tuple[StageType, Blob]]]:
        """
        :return:
            Dict(path : list(tuple(stage, Blob, ...))), being a dictionary associating a
            path in the index with a list containing sorted stage/blob pairs.

        :note:
            Blobs that have been removed in one side simply do not exist in the given
            stage. That is, a file removed on the 'other' branch whose entries are at
            stage 3 will not have a stage 3 entry.
        """

        def is_unmerged_blob(t: Tuple[StageType, Blob]) -> bool:
            return t[0] != 0

        path_map: Dict[PathLike, List[Tuple[StageType, Blob]]] = {}
        for stage, blob in self.iter_blobs(is_unmerged_blob):
            path_map.setdefault(blob.path, []).append((stage, blob))
        # END for each unmerged blob
        for line in path_map.values():
            line.sort()

        return path_map

    @classmethod
    def entry_key(cls, *entry: Union[BaseIndexEntry, PathLike, StageType]) -> Tuple[PathLike, StageType]:
        return entry_key(*entry)

    def resolve_blobs(self, iter_blobs: Iterator[Blob]) -> "IndexFile":
        """Resolve the blobs given in blob iterator.

        This will effectively remove the index entries of the respective path at all
        non-null stages and add the given blob as new stage null blob.

        For each path there may only be one blob, otherwise a :exc:`ValueError` will be
        raised claiming the path is already at stage 0.

        :raise ValueError:
            If one of the blobs already existed at stage 0.

        :return:
            self

        :note:
            You will have to write the index manually once you are done, i.e.
            ``index.resolve_blobs(blobs).write()``.
        """
        for blob in iter_blobs:
            stage_null_key = (blob.path, 0)
            if stage_null_key in self.entries:
                raise ValueError("Path %r already exists at stage 0" % str(blob.path))
            # END assert blob is not stage 0 already

            # Delete all possible stages.
            for stage in (1, 2, 3):
                try:
                    del self.entries[(blob.path, stage)]
                except KeyError:
                    pass
                # END ignore key errors
            # END for each possible stage

            self.entries[stage_null_key] = IndexEntry.from_blob(blob)
        # END for each blob

        return self

    def update(self) -> "IndexFile":
        """Reread the contents of our index file, discarding all cached information
        we might have.

        :note:
            This is a possibly dangerous operations as it will discard your changes to
            :attr:`index.entries <entries>`.

        :return:
            self
        """
        self._delete_entries_cache()
        self._dirty_paths.clear()
        # Allows to lazily reread on demand.
        return self

    def write_tree(self) -> Tree:
        """Write this index to a corresponding :class:`~git.objects.tree.Tree` object
        into the repository's object database and return it.

        :return:
            :class:`~git.objects.tree.Tree` object representing this index.

        :note:
            The tree will be written even if one or more objects the tree refers to does
            not yet exist in the object database. This could happen if you added entries
            to the index directly.

        :raise git.exc.UnmergedEntriesError:
        """
        for entry in self.entries.values():
            if entry.stage:
                raise UnmergedEntriesError(entry)
        entries = self._validated_entries()
        native = _backend.write_tree(
            self.repo.git, [(os.fsencode(entry.path), entry.mode, entry.hexsha) for entry in entries.values()]
        )
        if native is not NotImplemented:
            return Tree(self.repo, bytes.fromhex(native), path="")
        with self._materialized_index() as path:
            oid = self.repo.git._call_process_safe("write_tree", "--missing-ok", env={"GIT_INDEX_FILE": path})
        return Tree(self.repo, bytes.fromhex(oid), path="")

    def _process_diff_args(
        self,
        args: List[Union[PathLike, "git_diff.Diffable"]],
    ) -> List[Union[PathLike, "git_diff.Diffable"]]:
        try:
            args.pop(args.index(self))
        except IndexError:
            pass
        # END remove self
        return args

    def _to_relative_path(self, path: PathLike) -> PathLike:
        """
        :return:
            Version of path relative to our git directory or raise :exc:`ValueError` if
            it is not within our git directory.

        :raise ValueError:
        """
        if self.repo.bare:
            drive, _tail = osp.splitdrive(os.fspath(path))
            if drive or _is_path_rooted(path):
                raise InvalidGitRepositoryError("paths with a drive or root require a non-bare repository")
            return path
        return _to_relative_path(cast(PathLike, self.repo.working_tree_dir), path)

    def _preprocess_add_items(
        self, items: Union[PathLike, Sequence[Union[PathLike, Blob, BaseIndexEntry, "Submodule"]]]
    ) -> Tuple[List[PathLike], List[BaseIndexEntry]]:
        """Split the items into two lists of path strings and BaseEntries."""
        paths = []
        entries = []
        # if it is a string put in list
        if isinstance(items, (str, os.PathLike)):
            items = [items]

        for item in items:
            if isinstance(item, (str, os.PathLike)):
                paths.append(self._to_relative_path(item))
            elif isinstance(item, (Blob, Submodule)):
                entries.append(BaseIndexEntry.from_blob(item))
            elif isinstance(item, BaseIndexEntry):
                entries.append(item)
            else:
                raise TypeError("Invalid Type: %r" % item)
        # END for each item
        for entry in entries:
            _validate_repo_path(entry.path)
        return paths, entries

    def _store_path(self, filepath: PathLike, fprogress: Callable) -> BaseIndexEntry:
        """Store file at filepath in the database and return the base index entry.

        :note:
            This needs the :func:`~git.index.util.git_working_dir` decorator active!
            This must be ensured in the calling code.
        """
        filepath = self._to_relative_path(filepath)
        _validate_repo_path(filepath)
        parent = osp.realpath(self.repo.working_dir)
        for component in os.fspath(filepath).split("/")[:-1]:
            parent = osp.join(parent, component)
            if osp.islink(parent) or osp.normcase(osp.realpath(parent)) != osp.normcase(osp.abspath(parent)):
                raise ValueError("Cannot stage a path beyond a symbolic link: %r" % filepath)
        st = os.lstat(filepath)
        if not S_ISLNK(st.st_mode) and not S_ISREG(st.st_mode):
            raise ValueError("Can only stage a regular file or symbolic link: %r" % filepath)

        stream_size = st.st_size
        if S_ISLNK(st.st_mode):
            # readlink is a string, but we need bytes.
            target = force_bytes(os.readlink(filepath), encoding=defenc)
            stream_size = len(target)

            def open_stream() -> BinaryIO:
                return BytesIO(target)
        else:

            def open_stream() -> BinaryIO:
                # Do not follow a final symlink or block on a FIFO substituted
                # between lstat and open on platforms supporting these flags.
                def opener(path: str, flags: int) -> int:
                    return os.open(path, flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))

                return open(filepath, "rb", opener=opener)

        with open_stream() as stream:
            if not S_ISLNK(st.st_mode):
                st = os.fstat(stream.fileno())
                if not S_ISREG(st.st_mode):
                    raise ValueError("Can only stage a regular file: %r" % filepath)
                stream_size = st.st_size
            fprogress(filepath, False, filepath)
            istream = self.repo.odb.store(IStream(Blob.type, stream_size, stream))
            fprogress(filepath, True, filepath)
        return BaseIndexEntry(
            (
                stat_mode_to_index_mode(st.st_mode),
                istream.binsha,
                0,
                to_native_path_linux(filepath),
            )
        )

    @unbare_repo
    @git_working_dir
    def _entries_for_paths(
        self,
        paths: List[str],
        path_rewriter: Union[Callable, None],
        fprogress: Callable,
        entries: List[BaseIndexEntry],
    ) -> List[BaseIndexEntry]:
        entries_added: List[BaseIndexEntry] = []
        if path_rewriter:
            working_tree_dir = self.repo.working_tree_dir
            if working_tree_dir is None:
                raise InvalidGitRepositoryError("Cannot rewrite paths without a working tree")
            working_tree_dir = str(working_tree_dir)
            for path in paths:
                if osp.isabs(path):
                    abspath = path
                    gitrelative_path = path[len(working_tree_dir) + 1 :]
                else:
                    gitrelative_path = path
                    abspath = osp.join(working_tree_dir, gitrelative_path)
                # END obtain relative and absolute paths

                blob = Blob(
                    self.repo,
                    self.repo._null_binsha,
                    stat_mode_to_index_mode(os.lstat(abspath).st_mode),
                    to_native_path_linux(gitrelative_path),
                )
                # TODO: variable undefined
                entries.append(BaseIndexEntry.from_blob(blob))
            # END for each path
            del paths[:]
        # END rewrite paths

        # HANDLE PATHS
        assert len(entries_added) == 0
        for filepath in self._iter_expand_paths(paths):
            entries_added.append(self._store_path(filepath, fprogress))
        # END for each filepath
        # END path handling
        return entries_added

    def add(
        self,
        items: Union[PathLike, Sequence[Union[PathLike, Blob, BaseIndexEntry, "Submodule"]]],
        force: bool = True,
        fprogress: Callable = lambda *args: None,
        path_rewriter: Union[Callable[..., PathLike], None] = None,
        write: bool = True,
        write_extension_data: bool = False,
    ) -> List[BaseIndexEntry]:
        R"""Add files from the working tree, specific blobs, or
        :class:`~git.index.typ.BaseIndexEntry`\s to the index.

        :param items:
            Multiple types of items are supported, types can be mixed within one call.
            Different types imply a different handling. File paths may generally be
            relative or absolute.

            - path string

                Strings denote a relative or absolute path into the repository pointing
                to an existing file, e.g., ``CHANGES``, ``lib/myfile.ext``,
                ``/home/gitrepo/lib/myfile.ext``.

                Absolute paths must start with working tree directory of this index's
                repository to be considered valid. For example, if it was initialized
                with a non-normalized path, like ``/root/repo/../repo``, absolute paths
                to be added must start with ``/root/repo/../repo``.

                Paths provided like this must exist. When added, they will be written
                into the object database.

                PathStrings may contain globs, such as ``lib/__init__*``. Or they can be
                directories like ``lib``, which will add all the files within the
                directory and subdirectories.

                This equals a straight :manpage:`git-add(1)`.

                They are added at stage 0.

            - :class:`~git.objects.blob.Blob` or
              :class:`~git.objects.submodule.base.Submodule` object

                Blobs are added as they are assuming a valid mode is set.

                The file they refer to may or may not exist in the file system, but must
                be a path relative to our repository.

                If their object ID is all zeroes, their path must exist in the file system
                relative to the git repository as an object will be created from the
                data at the path.

                The handling now very much equals the way string paths are processed,
                except that the mode you have set will be kept. This allows you to
                create symlinks by settings the mode respectively and writing the target
                of the symlink directly into the file. This equals a default Linux
                symlink which is not dereferenced automatically, except that it can be
                created on filesystems not supporting it as well.

                Please note that globs or directories are not allowed in
                :class:`~git.objects.blob.Blob` objects.

                They are added at stage 0.

            - :class:`~git.index.typ.BaseIndexEntry` or type

                Handling equals the one of :class:`~git.objects.blob.Blob` objects, but
                the stage may be explicitly set. Please note that Index Entries require
                binary sha's.

        :param force:
            **CURRENTLY INEFFECTIVE**
            If ``True``, otherwise ignored or excluded files will be added anyway. As
            opposed to the :manpage:`git-add(1)` command, we enable this flag by default
            as the API user usually wants the item to be added even though they might be
            excluded.

        :param fprogress:
            Function with signature ``f(path, done=False, item=item)`` called for each
            path to be added, one time once it is about to be added where ``done=False``
            and once after it was added where ``done=True``.

            ``item`` is set to the actual item we handle, either a path or a
            :class:`~git.index.typ.BaseIndexEntry`.

            Please note that the processed path is not guaranteed to be present in the
            index already as the index is currently being processed.

        :param path_rewriter:
            Function, with signature ``(string) func(BaseIndexEntry)``, returning a path
            for each passed entry which is the path to be actually recorded for the
            object created from :attr:`entry.path <git.index.typ.BaseIndexEntry.path>`.
            This allows you to write an index which is not identical to the layout of
            the actual files on your hard-disk. If not ``None`` and `items` contain
            plain paths, these paths will be converted to Entries beforehand and passed
            to the path_rewriter. Please note that ``entry.path`` is relative to the git
            repository.

        :param write:
            If ``True``, the index will be written once it was altered. Otherwise the
            changes only exist in memory and are not available to git commands.

        :param write_extension_data:
            Retained for compatibility. Git manages index extensions and invalidates
            cached trees automatically when entries change.

        :return:
            List of :class:`~git.index.typ.BaseIndexEntry`\s representing the entries
            just actually added.

        :raise OSError:
            If a supplied path did not exist. Please note that
            :class:`~git.index.typ.BaseIndexEntry` objects that do not have a null sha
            will be added even if their paths do not exist.
        """
        # Sort the entries into strings and Entries.
        # Blobs are converted to entries automatically.
        # Paths can be git-added. For everything else we use git-update-index.
        paths, entries = self._preprocess_add_items(items)
        entries_added: List[BaseIndexEntry] = []
        # This code needs a working tree, so we try not to run it unless required.
        # That way, we are OK on a bare repository as well.
        # If there are no paths, the rewriter has nothing to do either.
        if paths:
            entries_added.extend(self._entries_for_paths(paths, path_rewriter, fprogress, entries))

        # HANDLE ENTRIES
        if entries:
            null_mode_entries = [e for e in entries if e.mode == 0]
            if null_mode_entries:
                raise ValueError(
                    "At least one Entry has a null-mode - please use index.remove to remove files for clarity"
                )
            # END null mode should be remove

            # HANDLE ENTRY OBJECT CREATION
            # Create objects if required, otherwise go with the existing shas.
            null_entries_indices = [i for i, e in enumerate(entries) if not any(e.binsha)]
            if null_entries_indices:

                @git_working_dir
                def handle_null_entries(self: "IndexFile") -> None:
                    for ei in null_entries_indices:
                        null_entry = entries[ei]
                        new_entry = self._store_path(null_entry.path, fprogress)

                        # Update null entry.
                        entries[ei] = BaseIndexEntry(
                            (
                                null_entry.mode,
                                new_entry.binsha,
                                null_entry.flags,
                                null_entry.path,
                            )
                        )
                    # END for each entry index

                # END closure

                handle_null_entries(self)
            # END null_entry handling

            # REWRITE PATHS
            # If we have to rewrite the entries, do so now, after we have generated all
            # object sha's.
            if path_rewriter:
                for i, e in enumerate(entries):
                    entries[i] = BaseIndexEntry((e.mode, e.binsha, e.flags, path_rewriter(e)))
                # END for each entry
            # END handle path rewriting

            # Just go through the remaining entries and provide progress info.
            for i, entry in enumerate(entries):
                progress_sent = i in null_entries_indices
                if not progress_sent:
                    fprogress(entry.path, False, entry)
                    fprogress(entry.path, True, entry)
                # END handle progress
            # END for each entry
            entries_added.extend(entries)
        # END if there are base entries

        # FINALIZE
        # Add the new entries to this instance.
        for entry in entries_added:
            _validate_repo_path(entry.path)
        for entry in entries_added:
            self.entries[(entry.path, entry.stage)] = IndexEntry.from_base(entry)
            self._dirty_paths.add(os.fspath(entry.path))

        if write:
            self.write(ignore_extension_data=not write_extension_data)
        # END handle write

        return entries_added

    def _items_to_rela_paths(
        self,
        items: Union[PathLike, Sequence[Union[PathLike, BaseIndexEntry, Blob, Submodule]]],
    ) -> List[PathLike]:
        """Returns a list of repo-relative paths from the given items which
        may be absolute or relative paths, entries or blobs."""
        paths = []
        # If string, put in list.
        if isinstance(items, (str, os.PathLike)):
            items = [items]

        for item in items:
            if isinstance(item, (BaseIndexEntry, (Blob, Submodule))):
                paths.append(self._to_relative_path(item.path))
            elif isinstance(item, (str, os.PathLike)):
                paths.append(self._to_relative_path(item))
            else:
                raise TypeError("Invalid item type: %r" % item)
        # END for each item
        for path in paths:
            if path not in (".", "./"):
                _validate_repo_path(os.fspath(path).rstrip("/"))
        return paths

    @post_clear_cache
    @default_index
    def remove(
        self,
        items: Union[PathLike, Sequence[Union[PathLike, Blob, BaseIndexEntry, "Submodule"]]],
        working_tree: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> List[str]:
        R"""Remove the given items from the index and optionally from the working tree
        as well.

        :param items:
            Multiple types of items are supported which may be be freely mixed.

            - path string

                Remove the given path at all stages. If it is a directory, you must
                specify the ``r=True`` keyword argument to remove all file entries below
                it. If absolute paths are given, they will be converted to a path
                relative to the git repository directory containing the working tree

                The path string may include globs, such as ``*.c``.

            - :class:`~git.objects.blob.Blob` object

                Only the path portion is used in this case.

            - :class:`~git.index.typ.BaseIndexEntry` or compatible type

                The only relevant information here is the path. The stage is ignored.

        :param working_tree:
            If ``True``, the entry will also be removed from the working tree,
            physically removing the respective file. This may fail if there are
            uncommitted changes in it.

        :param allow_unsafe_options:
            Allow unsafe options such as ``--pathspec-from-file`` to be passed to
            :manpage:`git-rm(1)`.

        :param kwargs:
            Additional keyword arguments to be passed to :manpage:`git-rm(1)`, such as
            ``r`` to allow recursive removal.

        :return:
            List(path_string, ...) list of repository relative paths that have been
            removed effectively.

            This is interesting to know in case you have provided a directory or globs.
            Paths are relative to the repository.
        """
        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([], kwargs),
                unsafe_options=Git.unsafe_git_pathspec_from_file_options,
            )
        args = []
        if not working_tree:
            args.append("--cached")
        args.append("--")

        # Preprocess paths.
        paths = list(map(os.fspath, self._items_to_rela_paths(items)))  # type: ignore[arg-type]
        removed_paths = self.repo.git._call_process_safe("rm", args, paths, **kwargs).splitlines()

        # Process output to gain proper paths.
        # rm 'path'
        return [p[4:-1] for p in removed_paths]

    @post_clear_cache
    @default_index
    def move(
        self,
        items: Union[PathLike, Sequence[Union[PathLike, Blob, BaseIndexEntry, "Submodule"]]],
        skip_errors: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> List[Tuple[str, str]]:
        """Rename/move the items, whereas the last item is considered the destination of
        the move operation.

        If the destination is a file, the first item (of two) must be a file as well.

        If the destination is a directory, it may be preceded by one or more directories
        or files.

        The working tree will be affected in non-bare repositories.

        :param items:
            Multiple types of items are supported, please see the :meth:`remove` method
            for reference.

        :param skip_errors:
            If ``True``, errors such as ones resulting from missing source files will be
            skipped.

        :param allow_unsafe_options:
            Allow unsafe options such as ``--pathspec-from-file`` to be passed to
            :manpage:`git-mv(1)`.

        :param kwargs:
            Additional arguments you would like to pass to :manpage:`git-mv(1)`, such as
            ``dry_run`` or ``force``.

        :return:
            List(tuple(source_path_string, destination_path_string), ...)

            A list of pairs, containing the source file moved as well as its actual
            destination. Relative to the repository root.

        :raise ValueError:
            If only one item was given.

        :raise git.exc.GitCommandError:
            If git could not handle your request.
        """
        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([], kwargs),
                unsafe_options=Git.unsafe_git_pathspec_from_file_options,
            )
        args = []
        if skip_errors:
            args.append("-k")
        args.append("--")

        paths = self._items_to_rela_paths(items)
        if len(paths) < 2:
            raise ValueError("Please provide at least one source and one destination of the move operation")

        was_dry_run = kwargs.pop("dry_run", kwargs.pop("n", None))
        kwargs["dry_run"] = True

        # First execute rename in dry run so the command tells us what it actually does
        # (for later output).
        out = []
        mvlines = self.repo.git._call_process_safe("mv", args, paths, **kwargs).splitlines()

        # Parse result - first 0:n/2 lines are 'checking ', the remaining ones are the
        # 'renaming' ones which we parse.
        for ln in range(int(len(mvlines) / 2), len(mvlines)):
            tokens = mvlines[ln].split(" to ")
            assert len(tokens) == 2, "Too many tokens in %s" % mvlines[ln]

            # [0] = Renaming x
            # [1] = y
            out.append((tokens[0][9:], tokens[1]))
        # END for each line to parse

        # Either prepare for the real run, or output the dry-run result.
        if was_dry_run:
            return out
        # END handle dry run

        # Now apply the actual operation.
        kwargs.pop("dry_run")
        self.repo.git._call_process_safe("mv", args, paths, **kwargs)

        return out

    def commit(
        self,
        message: str,
        parent_commits: Union[List[Commit], None] = None,
        head: bool = True,
        author: Union[None, Actor] = None,
        committer: Union[None, Actor] = None,
        author_date: Union[datetime.datetime, str, None] = None,
        commit_date: Union[datetime.datetime, str, None] = None,
        skip_hooks: bool = False,
        trailers: Union[None, "Dict[str, str]", "List[Tuple[str, str]]"] = None,
    ) -> Commit:
        """Commit the current default index file, creating a
        :class:`~git.objects.commit.Commit` object.

        For more information on the arguments, see
        :meth:`Commit.create_from_tree <git.objects.commit.Commit.create_from_tree>`.

        :note:
            If you have manually altered the :attr:`entries` member of this instance,
            don't forget to :meth:`write` your changes to disk beforehand.

        :note:
            Passing ``skip_hooks=True`` is the equivalent of using ``-n`` or
            ``--no-verify`` on the command line.

        :return:
            :class:`~git.objects.commit.Commit` object representing the new commit
        """
        if not skip_hooks and not osp.isdir(osp.dirname(self.path)):
            original_path = self.path
            with self._materialized_index() as path:
                self._file_path = path
                try:
                    return self.commit(
                        message, parent_commits, head, author, committer, author_date, commit_date, skip_hooks, trailers
                    )
                finally:
                    self._file_path = original_path
        if not skip_hooks:
            # Hooks must see staged changes and their own updates must remain in the index.
            self.write()
            run_commit_hook("pre-commit", self)
            self._delete_entries_cache()
            self._write_commit_editmsg(message)
            try:
                run_commit_hook("commit-msg", self, self._commit_editmsg_filepath())
                message = self._read_commit_editmsg()
            finally:
                self._remove_commit_editmsg()
        tree = self.write_tree()
        rval = Commit.create_from_tree(
            self.repo,
            tree,
            message,
            parent_commits,
            head,
            author=author,
            committer=committer,
            author_date=author_date,
            commit_date=commit_date,
            trailers=trailers,
        )
        if not skip_hooks:
            run_commit_hook("post-commit", self)
        return rval

    def _write_commit_editmsg(self, message: str) -> None:
        with open(self._commit_editmsg_filepath(), "wb") as commit_editmsg_file:
            commit_editmsg_file.write(message.encode(defenc))

    def _remove_commit_editmsg(self) -> None:
        os.remove(self._commit_editmsg_filepath())

    def _read_commit_editmsg(self) -> str:
        with open(self._commit_editmsg_filepath(), "rb") as commit_editmsg_file:
            return commit_editmsg_file.read().decode(defenc)

    def _commit_editmsg_filepath(self) -> str:
        return self.repo.git._call_process_safe("rev_parse", "--path-format=absolute", "--git-path", "COMMIT_EDITMSG")

    def _flush_stdin_and_wait(self, proc: "Popen[bytes]", ignore_stdout: bool = False) -> bytes:
        stdin_IO = proc.stdin
        if stdin_IO:
            stdin_IO.flush()
            stdin_IO.close()

        stdout = b""
        if not ignore_stdout and proc.stdout:
            stdout = proc.stdout.read()

        if proc.stdout:
            proc.stdout.close()
            proc.wait()
        return stdout

    @default_index
    def checkout(
        self,
        paths: Union[None, PathLike, Iterable[PathLike]] = None,
        force: bool = False,
        fprogress: Callable = lambda *args: None,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> Union[None, Iterator[PathLike], Sequence[PathLike]]:
        """Check out the given paths or all files from the version known to the index
        into the working tree.

        :note:
            Be sure you have written pending changes using the :meth:`write` method in
            case you have altered the entries dictionary directly.

        :param paths:
            If ``None``, all paths in the index will be checked out.
            Otherwise an iterable of relative or absolute paths or a single path
            pointing to files or directories in the index is expected.

        :param force:
            If ``True``, existing files will be overwritten even if they contain local
            modifications.
            If ``False``, these will trigger a :exc:`~git.exc.CheckoutError`.

        :param fprogress:
            See :meth:`IndexFile.add` for signature and explanation.

            The provided progress information will contain ``None`` as path and item if
            no explicit paths are given. Otherwise progress information will be send
            prior and after a file has been checked out.

        :param allow_unsafe_options:
            Allow unsafe options, such as ``--prefix``.

        :param kwargs:
            Additional arguments to be passed to :manpage:`git-checkout-index(1)`.

        :return:
            Iterable yielding paths to files which have been checked out and are
            guaranteed to match the version stored in the index.

        :raise git.exc.CheckoutError:
            * If at least one file failed to be checked out. This is a summary, hence it
              will checkout as many files as it can anyway.
            * If one of files or directories do not exist in the index (as opposed to
              the original git command, which ignores them).

        :raise git.exc.GitCommandError:
            If error lines could not be parsed - this truly is an exceptional state.

        :note:
            The checkout is limited to checking out the files in the index. Files which
            are not in the index anymore and exist in the working tree will not be
            deleted. This behaviour is fundamentally different to ``head.checkout``,
            i.e. if you want :manpage:`git-checkout(1)`-like behaviour, use
            ``head.checkout`` instead of ``index.checkout``.
        """
        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([], kwargs),
                unsafe_options=self.unsafe_git_checkout_index_options,
            )

        args = ["--index", "-z"]
        if force:
            args.append("--force")

        failed_files = []
        failed_reasons = []
        unknown_lines = []

        def handle_stderr(proc: "Popen[bytes]", iter_checked_out_files: Iterable[PathLike]) -> None:
            stderr_IO = proc.stderr
            if not stderr_IO:
                return  # Return early if stderr empty.

            stderr_bytes = stderr_IO.read()
            # line contents:
            stderr = stderr_bytes.decode(defenc)
            # git-checkout-index: this already exists
            endings = (
                " already exists",
                " is not in the cache",
                " does not exist at stage",
                " is unmerged",
            )
            for line in stderr.splitlines():
                if not line.startswith("git checkout-index: ") and not line.startswith("git-checkout-index: "):
                    is_a_dir = " is a directory"
                    unlink_issue = "unable to unlink old '"
                    already_exists_issue = " already exists, no checkout"  # created by entry.c:checkout_entry(...)
                    if line.endswith(is_a_dir):
                        failed_files.append(line[: -len(is_a_dir)])
                        failed_reasons.append(is_a_dir)
                    elif line.startswith(unlink_issue):
                        failed_files.append(line[len(unlink_issue) : line.rfind("'")])
                        failed_reasons.append(unlink_issue)
                    elif line.endswith(already_exists_issue):
                        failed_files.append(line[: -len(already_exists_issue)])
                        failed_reasons.append(already_exists_issue)
                    else:
                        unknown_lines.append(line)
                    continue
                # END special lines parsing

                for e in endings:
                    if line.endswith(e):
                        failed_files.append(line[20 : -len(e)])
                        failed_reasons.append(e)
                        break
                    # END if ending matches
                # END for each possible ending
            # END for each line
            if unknown_lines:
                raise GitCommandError(("git-checkout-index",), 128, stderr)
            if failed_files:
                valid_files = list(set(iter_checked_out_files) - set(failed_files))
                raise CheckoutError(
                    "Some files could not be checked out from the index due to local modifications",
                    failed_files,
                    valid_files,
                    failed_reasons,
                )

        # END stderr handler

        # Read and validate the index before Git trusts its paths for checkout.
        self._delete_entries_cache()
        self.entries  # noqa: B018
        if paths is None:
            args.append("--all")
            kwargs["as_process"] = 1
            fprogress(None, False, None)
            proc = self.repo.git._call_process_safe("checkout_index", *args, **kwargs)
            proc.wait()
            fprogress(None, True, None)
            rval_iter = (e.path for e in self.entries.values())
            handle_stderr(proc, rval_iter)
            return rval_iter
        else:
            if isinstance(paths, (str, os.PathLike)):
                paths = [paths]
            else:
                paths = list(paths)
            for path in paths:
                _validate_repo_path(os.fspath(self._to_relative_path(path)).rstrip("/"))

            # Make sure we have our entries loaded before we start checkout_index, which
            # will hold a lock on it. We try to get the lock as well during our entries
            # initialization.
            self.entries  # noqa: B018

            args.append("--stdin")
            kwargs["as_process"] = True
            kwargs["istream"] = subprocess.PIPE
            proc = self.repo.git._call_process_safe("checkout_index", args, **kwargs)

            # FIXME: Reading from GIL!
            def make_exc() -> GitCommandError:
                return GitCommandError(("git-checkout-index", *args), 128, proc.stderr.read())

            checked_out_files: List[PathLike] = []

            for path in paths:
                co_path = to_native_path_linux(self._to_relative_path(path))
                # If the item is not in the index, it could be a directory.
                path_is_directory = False

                try:
                    self.entries[(co_path, 0)]
                except KeyError:
                    folder = co_path
                    if not folder.endswith("/"):
                        folder += "/"
                    for entry in self.entries.values():
                        if os.fspath(entry.path).startswith(folder):
                            p = entry.path
                            self._write_path_to_stdin(proc, p, p, make_exc, fprogress, read_from_stdout=False)
                            checked_out_files.append(p)
                            path_is_directory = True
                        # END if entry is in directory
                    # END for each entry
                # END path exception handlnig

                if not path_is_directory:
                    self._write_path_to_stdin(proc, co_path, path, make_exc, fprogress, read_from_stdout=False)
                    checked_out_files.append(co_path)
                # END path is a file
            # END for each path
            try:
                self._flush_stdin_and_wait(proc, ignore_stdout=True)
            except GitCommandError:
                # Without parsing stdout we don't know what failed.
                raise CheckoutError(  # noqa: B904
                    "Some files could not be checked out from the index, probably because they didn't exist.",
                    failed_files,
                    [],
                    failed_reasons,
                )

            handle_stderr(proc, checked_out_files)
            return checked_out_files
        # END paths handling

    @default_index
    def reset(
        self,
        commit: Union[Commit, "Reference", str] = "HEAD",
        working_tree: bool = False,
        paths: Union[None, Iterable[PathLike]] = None,
        head: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> "IndexFile":
        """Reset the index to reflect the tree at the given commit. This will not adjust
        our HEAD reference by default, as opposed to
        :meth:`HEAD.reset <git.refs.head.HEAD.reset>`.

        :param commit:
            Revision, :class:`~git.refs.reference.Reference` or
            :class:`~git.objects.commit.Commit` specifying the commit we should
            represent.

            If you want to specify a tree only, use :meth:`IndexFile.from_tree` and
            overwrite the default index.

        :param working_tree:
            If ``True``, the files in the working tree will reflect the changed index.
            If ``False``, the working tree will not be touched.
            Please note that changes to the working copy will be discarded without
            warning!

        :param head:
            If ``True``, the head will be set to the given commit. This is ``False`` by
            default, but if ``True``, this method behaves like
            :meth:`HEAD.reset <git.refs.head.HEAD.reset>`.

        :param paths:
            If given as an iterable of absolute or repository-relative paths, only these
            will be reset to their state at the given commit-ish.
            The paths need to exist at the commit, otherwise an exception will be
            raised.

        :param allow_unsafe_options:
            Allow options that may write to arbitrary paths.

        :param kwargs:
            Additional keyword arguments passed to :manpage:`git-reset(1)`.

        :note:
            :meth:`IndexFile.reset`, as opposed to
            :meth:`HEAD.reset <git.refs.head.HEAD.reset>`, will not delete any files in
            order to maintain a consistent working tree. Instead, it will just check out
            the files according to their state in the index.
            If you want :manpage:`git-reset(1)`-like behaviour, use
            :meth:`HEAD.reset <git.refs.head.HEAD.reset>` instead.

        :return:
            self
        """
        # What we actually want to do is to merge the tree into our existing index,
        # which is what git-read-tree does.
        new_inst = type(self).from_tree(self.repo, commit, allow_unsafe_options=allow_unsafe_options)
        if not paths:
            self.entries = new_inst.entries
        else:
            nie = new_inst.entries
            for path in paths:
                path = self._to_relative_path(path)
                key = entry_key(path, 0)
                try:
                    self.entries[key] = nie[key]
                except KeyError:
                    # If key is not in theirs, it mustn't be in ours.
                    try:
                        del self.entries[key]
                    except KeyError:
                        pass
                    # END handle deletion keyerror
                # END handle keyerror
            # END for each path
        # END handle paths
        self.write()

        if working_tree:
            self.checkout(paths=paths, force=True)
        # END handle working tree

        if head:
            self.repo.head.set_commit(self.repo.commit(commit), logmsg="%s: Updating HEAD" % commit)
        # END handle head change

        return self

    def diff(
        self,
        other: Union[
            Literal[git_diff.DiffConstants.INDEX],
            Literal[git_diff.DiffConstants.NULL_TREE],
            "Tree",
            "Commit",
            str,
            None,
        ] = git_diff.INDEX,
        paths: Union[PathLike, List[PathLike], Tuple[PathLike, ...], None] = None,
        create_patch: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> git_diff.DiffIndex[git_diff.Diff]:
        """Diff this index against the working copy or a :class:`~git.objects.tree.Tree`
        or :class:`~git.objects.commit.Commit` object.

        For documentation of the parameters and return values, see
        :meth:`Diffable.diff <git.diff.Diffable.diff>`.

        :note:
            Will only work with indices that represent the default git index as they
            have not been initialized with a stream.
        """
        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([other], kwargs),
                unsafe_options=self.repo.unsafe_git_diff_options,
                clusterable_short_options="46abceflmnpqrstuvwzBCDMNRW",
            )

        # Only run if we are the default repository index.
        if self._file_path != self._index_path():
            raise AssertionError("Cannot call %r on indices that do not represent the default git index" % self.diff())
        # Index against index is always empty.
        if other is self.INDEX:
            return git_diff.DiffIndex()

        if other == git_diff.NULL_TREE or other == git_diff.NULL_TREE_SHA:
            args: List[Union[PathLike, str]] = [
                "--cached",
                self.repo._empty_tree_hexsha,
                "--no-abbrev",
                "--full-index",
            ]

            if not any(x in kwargs for x in ("find_renames", "no_renames", "M")):
                args.append("-M")

            if create_patch:
                args.append("-p")
                args.append("--no-ext-diff")
            else:
                args.append("--raw")
                args.append("-z")

            args.append("--no-color")

            if paths is not None and not isinstance(paths, (tuple, list)):
                paths = [paths]

            if paths:
                args.append("--")
                args.extend(paths)

            kwargs["as_process"] = True
            if create_patch:
                kwargs["_config"] = ["diff.mnemonicPrefix=false"]
            proc = self.repo.git._call_process_safe("diff", *args, **kwargs)

            diff_method = (
                git_diff.Diff._index_from_patch_format if create_patch else git_diff.Diff._index_from_raw_format
            )
            index = diff_method(self.repo, proc)

            proc.wait()
            return index

        # Index against anything but None is a reverse diff with the respective item.
        # Handle existing -R flags properly.
        # Transform strings to the object so that we can call diff on it.
        if isinstance(other, str):
            other = self.repo.rev_parse(other)
        # END object conversion

        if isinstance(other, Object):  # For Tree or Commit.
            # Invert the existing R flag.
            cur_val = kwargs.get("R", False)
            kwargs["R"] = not cur_val
            return other.diff(
                self.INDEX,
                paths,
                create_patch,
                allow_unsafe_options=allow_unsafe_options,
                **kwargs,
            )
        # END diff against other item handling

        # If other is not None here, something is wrong.
        if other is not None:
            raise ValueError("other must be None, Diffable.INDEX, a Tree or Commit, was %r" % other)

        # Diff against working copy - can be handled by superclass natively.
        return super().diff(other, paths, create_patch, allow_unsafe_options=allow_unsafe_options, **kwargs)
