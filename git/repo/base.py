# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

from __future__ import annotations

__all__ = ["Repo"]

import gc
import logging
import os
import os.path as osp
import re
import shlex
import sys
import tempfile
from threading import RLock
import warnings
import weakref

import gitdb
import gitdb.util
from gitdb.db.loose import LooseObjectDB
from gitdb.exc import BadObject

from git import _backend
from git.cmd import Git, handle_process_output
from git.compat import defenc, safe_decode
from git.config import GitConfigParser
from git.db import GitCmdObjectDB
from git.exc import (
    GitCommandError,
    InvalidGitRepositoryError,
    NoSuchPathError,
    UnsafeOptionError,
)
from git.index import IndexFile
from git.objects import Submodule, RootModule, Commit
from git.refs import HEAD, Head, Reference, TagReference
from git.remote import Remote, _T_RemoteName, add_progress, to_progress_instance
from git.util import (
    Actor,
    cygpath,
    expand_path,
    finalize_process,
    hex_to_bin,
    remove_password_if_present,
    to_native_path_linux,
)

from .fun import (
    rev_parse,
    to_commit,
    touch,
)

# typing ------------------------------------------------------

from git.types import (
    CallableProgress,
    Commit_ish,
    Lit_config_levels,
    PathLike,
    TBD,
    Tree_ish,
    assert_never,
)
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    TYPE_CHECKING,
    TextIO,
    Tuple,
    Type,
    Union,
    cast,
)

from git.types import ConfigLevels_Tup, TypedDict

if TYPE_CHECKING:
    from git.objects import Tree
    from git.objects.submodule.base import UpdateProgress
    from git.refs.symbolic import SymbolicReference
    from git.remote import RemoteProgress
    from git.util import IterableList

# -----------------------------------------------------------

_logger = logging.getLogger(__name__)


class BlameEntry(NamedTuple):
    commit: Commit
    linenos: range
    orig_path: Optional[str]
    orig_linenos: range


class Repo:
    """Represents a git repository and allows you to query references, create commit
    information, generate diffs, create and clone repositories, and query the log.

    The following attributes are worth using:

    * :attr:`working_dir` is the working directory of the git command, which is the
      working tree directory if available or the ``.git`` directory in case of bare
      repositories.

    * :attr:`working_tree_dir` is the working tree directory, but will return ``None``
      if we are a bare repository.

    * :attr:`git_dir` is the ``.git`` repository directory, which is always set.
    """

    DAEMON_EXPORT_FILE = "git-daemon-export-ok"

    # Must exist, or  __del__  will fail in case we raise on `__init__()`.
    git = cast("Git", None)
    _gix_repository: Any = None
    _gix_state: Any = None

    working_dir: PathLike
    """The working directory of the git command."""

    # stored as string for easier processing, but annotated as path for clearer intention
    _working_tree_dir: Optional[PathLike] = None

    git_dir: PathLike
    """The ``.git`` repository directory."""

    odb: Union[GitCmdObjectDB, LooseObjectDB, gitdb.GitDB]

    _common_dir: PathLike = ""

    # Precompiled regex
    re_whitespace = re.compile(r"\s+")
    re_hexsha_only = re.compile(r"^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$")
    re_hexsha_shortened = re.compile(r"^[0-9A-Fa-f]{4,64}$")
    re_envvars = re.compile(r"(\$(\{\s?)?[a-zA-Z_]\w*(\}\s?)?|%\s?[a-zA-Z_]\w*\s?%)")
    re_author_committer_start = re.compile(r"^(author|committer)")
    re_tab_full_line = re.compile(r"^\t(.*)$")

    unsafe_git_init_options = [
        # Can install hooks that execute during later Git commands:
        "--template",
        # Redirects the repository metadata to a caller-controlled path:
        "--separate-git-dir",
    ]
    """Options to :manpage:`git-init(1)` that permit unsafe code execution or I/O."""

    unsafe_git_clone_options = [
        # Executes arbitrary commands:
        "--upload-pack",
        "-u",
        # Can override configuration variables that execute arbitrary commands:
        "--config",
        "-c",
        # Can install hooks that execute during clone:
        "--template",
        # Redirects the repository metadata to a caller-controlled path:
        "--separate-git-dir",
        # Fetches from an additional caller-controlled URI:
        "--bundle-uri",
    ]
    """Options to :manpage:`git-clone(1)` that permit unsafe command execution or I/O.

    The ``--upload-pack``/``-u`` option allows users to execute arbitrary commands
    directly:
    https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---upload-packltupload-packgt

    The ``--config``/``-c`` option allows users to override configuration variables like
    ``protocol.allow`` and ``core.gitProxy`` to execute arbitrary commands:
    https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---configltkeygtltvaluegt

    The ``--template`` option can install hooks that execute during clone:
    https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---templatetemplate-directory

    The ``--bundle-uri`` option fetches from an additional URI before fetching from the
    clone URL. An untrusted value can therefore make Git access local files or
    unintended network resources:
    https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---bundle-uriuri
    """

    unsafe_git_archive_options = [
        # Allows arbitrary command execution through the remote git-upload-archive command.
        "--exec",
        # Writes output to a caller-controlled filesystem path.
        "--output",
        "-o",
        # Reads from a caller-controlled filesystem path:
        "--add-file",
        # Injects a caller-controlled path and contents:
        "--add-virtual-file",
    ]

    unsafe_git_revision_options = [
        # This option allows output to be written to arbitrary files before revision parsing.
        "--output",
        "-o",
    ]

    unsafe_git_blame_options = unsafe_git_revision_options + [
        # Runs a configured text conversion program.
        "--textconv",
        # These options read from arbitrary files and expose their contents through blame output.
        "--contents",
        "-S",
        "--ignore-revs-file",
    ]

    unsafe_git_diff_options = unsafe_git_revision_options + [
        # Treats path operands as arbitrary filesystem paths.
        "--no-index",
        # Reads caller-controlled order patterns from an arbitrary file.
        "-O",
        "--orderfile",
    ]

    # Invariants
    config_level: ConfigLevels_Tup = ("system", "user", "global", "repository")
    """Represents the configuration level of a configuration file."""

    # Subclass configuration
    GitCommandWrapperType = Git
    """Subclasses may easily bring in their own custom types by placing a constructor or
    type here."""

    def __init__(
        self,
        path: Optional[PathLike] = None,
        odbt: Type[Union[GitCmdObjectDB, LooseObjectDB, gitdb.GitDB]] = GitCmdObjectDB,
        search_parent_directories: bool = False,
        expand_vars: bool = True,
        *,
        _env: Optional[Mapping[str, Optional[str]]] = None,
    ) -> None:
        R"""Create a new :class:`Repo` instance.

        .. note::
            Repository storage, object formats, and reference backends are interpreted
            by GixPython when supported, otherwise Git (version 2.52 or newer).

        :param path:
            The path to either the worktree directory or the .git directory itself::

                repo = Repo("/Users/mtrier/Development/git-python")
                repo = Repo("/Users/mtrier/Development/git-python.git")
                repo = Repo("~/Development/git-python.git")
                repo = Repo("$REPOSITORIES/Development/git-python.git")
                repo = Repo(R"C:\Users\mtrier\Development\git-python\.git")

            - In *Cygwin*, `path` may be a ``cygdrive/...`` prefixed path.
            - If `path` is ``None`` or an empty string, :envvar:`GIT_DIR` is used. If
              that environment variable is absent or empty, the current directory is
              used.

        :param odbt:
            Object DataBase type - a type which is constructed by providing the
            directory containing the database objects, i.e. ``.git/objects``. It will be
            used to access all object data. The pure-Python ``GitDB`` backend is
            deprecated due to security and performance issues. Use the default
            :class:`~git.db.GitCmdObjectDB` instead.

        :param search_parent_directories:
            If ``True``, all parent directories will be searched for a valid repo as
            well.

            Please note that this was the default behaviour in older versions of
            GitPython, which is considered a bug though.

        :raise git.exc.InvalidGitRepositoryError:

        :raise git.exc.NoSuchPathError:

        :return:
            :class:`Repo`
        """

        # Clones can clear inherited source-storage variables without changing the
        # process environment. Apply these overrides to discovery and later calls.
        environment = dict(_env or {})
        git_dir_env = environment.pop("GIT_DIR", os.getenv("GIT_DIR"))
        object_dir_env = environment.get("GIT_OBJECT_DIRECTORY", os.getenv("GIT_OBJECT_DIRECTORY"))
        if object_dir_env is not None:
            object_dir_env = osp.abspath(object_dir_env)
        epath = path or git_dir_env
        if not epath:
            epath = os.getcwd()
        epath = os.fspath(epath)
        if Git.is_cygwin():
            # Given how the tests are written, this seems more likely to catch Cygwin
            # git used from Windows than Windows git used from Cygwin. Therefore
            # changing to Cygwin-style paths is the relevant operation.
            epath = cygpath(epath)

        if expand_vars and re.search(self.re_envvars, epath):
            warnings.warn(
                "The use of environment variables in paths is deprecated"
                + "\nfor security reasons and may be removed in the future!!",
                stacklevel=1,
            )
        epath = expand_path(epath, expand_vars)
        if epath is not None:
            if not os.path.exists(epath):
                raise NoSuchPathError(epath)

        # Resolve storage through Git. Absolutize environment paths before changing
        # the command's working directory, preserving Git's process-CWD semantics.
        for name in ("GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_WORK_TREE"):
            value = environment.get(name, os.environ.get(name))
            if value == "" and name != "GIT_WORK_TREE":
                raise InvalidGitRepositoryError(epath)
            if value is not None:
                environment[name] = osp.abspath(value)
        probe = self.GitCommandWrapperType(os.getcwd())
        probe._environment.update(GIT_DIR=None, **environment)
        explicit_git_dir = not path and bool(git_dir_env)
        assert epath is not None
        curpath = osp.abspath(os.fspath(epath))
        git_dir = None
        native = NotImplemented
        while curpath:
            dotgit = osp.join(curpath, ".git")
            candidate = curpath if explicit_git_dir or not osp.lexists(dotgit) else dotgit
            try:
                # Git resolves relative gitfile targets using the last forward
                # slash in this operand, including on Windows.
                native = _backend.discover_repository(candidate, environment)
                git_dir = (
                    probe._call_process_safe("rev_parse", "--resolve-git-dir", to_native_path_linux(candidate))
                    if native is NotImplemented
                    else os.fspath(native.git_dir())
                )
                git_dir = osp.abspath(git_dir)
                if osp.isfile(candidate):
                    # Git canonicalizes gitfile targets. Retain an equivalent
                    # caller spelling, e.g. /var instead of /private/var on macOS.
                    parent = osp.dirname(candidate)
                    try:
                        relative = osp.relpath(osp.realpath(git_dir), osp.realpath(parent))
                    except ValueError:
                        pass  # Gitfile targets may be on another Windows drive.
                    else:
                        spelling = osp.abspath(osp.join(parent, relative))
                        if osp.realpath(spelling) == osp.realpath(git_dir):
                            git_dir = spelling
                break
            except GitCommandError:
                # A malformed .git entry must not cause fallback to a parent repo.
                if candidate == dotgit or explicit_git_dir or not search_parent_directories:
                    break
            parent = osp.dirname(curpath)
            if parent == curpath:
                break
            curpath = parent
        if git_dir is None:
            raise InvalidGitRepositoryError(epath)

        self.git_dir = git_dir
        probe.update_environment(GIT_DIR=git_dir)
        try:
            if native is not NotImplemented:
                self.ref_format = probe._call_process_safe("rev_parse", "--show-ref-format")
            else:
                # Query the fixed scalar fields together, leaving the path last so
                # embedded newlines in the common directory remain unambiguous.
                metadata = probe._call_process_safe(
                    "rev_parse",
                    "--show-ref-format",
                    "--show-object-format",
                    "--is-bare-repository",
                    "--path-format=absolute",
                    "--git-common-dir",
                )
                self.ref_format, self.object_format, bare, self._common_dir = metadata.split("\n", 3)
                self._bare = bare == "true"
        except GitCommandError as exc:
            raise InvalidGitRepositoryError(epath) from exc
        if native is not NotImplemented:
            self._common_dir = to_native_path_linux(osp.abspath(native.common_dir()))
            self.object_format = str(native.object_hash())
            workdir = native.workdir()
            self._working_tree_dir = environment.get("GIT_WORK_TREE") or (
                to_native_path_linux(os.fspath(workdir)) if workdir is not None else None
            )
            # Gix's configured bare flag also applies to linked worktrees.
            self._bare = native.is_bare() and self._working_tree_dir is None
        else:
            self._working_tree_dir = environment.get("GIT_WORK_TREE")
            if self._working_tree_dir is None and not self._bare and environment.get("GIT_COMMON_DIR") is None:
                try:
                    probe._call_process_safe("config", "--get", "core.worktree")
                except GitCommandError as exc:
                    if exc.status != 1:
                        raise
                else:
                    # Let Git resolve relative paths and per-worktree configuration.
                    self._working_tree_dir = probe._call_process_safe("rev_parse", "--show-toplevel")
            if self._working_tree_dir is None:
                # The worktree registry also resolves administrative directories and
                # relative worktree metadata without interpreting gitdir/commondir files.
                listing = probe._call_process_safe("worktree", "list", "--porcelain", "-z")
                for record in listing.split("\0\0"):
                    fields = record.split("\0")
                    if not fields or not fields[0].startswith("worktree ") or "bare" in fields:
                        continue
                    worktree = fields[0][9:]
                    # Git only strips a forward-slash /.git suffix from its registry.
                    # A Windows gitdir file can instead contain a native backslash.
                    if osp.basename(worktree) == ".git" and osp.isfile(worktree):
                        worktree = osp.dirname(worktree)
                    try:
                        resolved = probe._call_process_safe(
                            "rev_parse", "--resolve-git-dir", to_native_path_linux(osp.join(worktree, ".git"))
                        )
                    except GitCommandError:
                        continue
                    if osp.realpath(resolved) == osp.realpath(git_dir):
                        self._working_tree_dir = worktree
                        self._bare = False
                        break
                if self._working_tree_dir is None:
                    try:
                        configured_bare = probe._call_process_safe(
                            "config", "--file", osp.join(self.common_dir, "config"), "--bool", "--get", "core.bare"
                        )
                        self._bare = configured_bare == "true"
                    except GitCommandError as exc:
                        if exc.status != 1:
                            raise
                if self._working_tree_dir is None and not self._bare:
                    self._working_tree_dir = osp.dirname(git_dir)
        if self._bare:
            self._working_tree_dir = None
        elif self._working_tree_dir is not None:
            # Preserve the caller's spelling of symlinked path prefixes (such as
            # /var on macOS), so absolute index paths remain relative to this repo.
            for spelling in (curpath, osp.dirname(curpath)):
                if osp.realpath(spelling) == osp.realpath(self._working_tree_dir):
                    self._working_tree_dir = spelling
                    break

        self.working_dir = self._working_tree_dir or self.common_dir
        self._gix_lock = RLock()
        self.git = self.GitCommandWrapperType(self.working_dir)
        self.git._repo = weakref.ref(self)
        self.git._environment.update(GIT_DIR=git_dir, **environment)
        if self._working_tree_dir is not None:
            self.git.update_environment(GIT_WORK_TREE=os.fspath(self._working_tree_dir))
        if native is not NotImplemented:
            self._gix_repository = native
            self._empty_tree_hexsha = str(native.empty_tree().id)
        else:
            with tempfile.TemporaryFile() as empty:
                self._empty_tree_hexsha = self.git._call_process_safe(
                    "hash_object", "-t", "tree", "--stdin", istream=empty
                )
        self._oid_size = len(self._empty_tree_hexsha) // 2
        self._null_binsha = bytes(self._oid_size)
        self._null_hexsha = "0" * (self._oid_size * 2)
        self.re_hexsha_only = re.compile(r"^[0-9A-Fa-f]{%d}$" % (self._oid_size * 2))
        self.re_hexsha_shortened = re.compile(r"^[0-9A-Fa-f]{4,%d}$" % (self._oid_size * 2))

        # Special handling, in special times.
        rootpath = object_dir_env if object_dir_env is not None else osp.join(self.common_dir, "objects")
        if issubclass(odbt, GitCmdObjectDB):
            self.odb = odbt(rootpath, self.git)
        else:
            if issubclass(odbt, gitdb.GitDB):
                warnings.warn(
                    "GitDB is deprecated as a GitPython backend due to security and performance issues. "
                    "Use the default GitCmdObjectDB backend instead.",
                    DeprecationWarning,
                    stacklevel=2,
                )
            self.odb = odbt(rootpath)

    def _get_gix_repository(
        self,
        *,
        command: Optional[Git] = None,
        env: Optional[Dict[str, Any]] = None,
        query_config: bool = False,
        recreate: bool = False,
    ) -> Any:
        """Access native state, reusing the repository unless recreation is requested.

        This method owns the reuse policy so it can later become configurable.
        Configuration queries currently open a separate handle without the execution
        restrictions applied to the retained handle. Other operations retain the
        existing best-effort refresh of configuration, environment and CLI changes.
        """
        with self._gix_lock:
            if recreate:
                self._gix_repository = self._gix_state = None
            return _backend._open_repository(
                command if command is not None else self.git, env or {}, query_config=query_config
            )

    def __getstate__(self) -> Dict[str, Any]:
        return {
            key: value
            for key, value in self.__dict__.items()
            if key not in ("_gix_repository", "_gix_state", "_gix_lock")
        }

    def __setstate__(self, state: Dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._gix_lock = RLock()
        self.git._repo = weakref.ref(self)

    def __enter__(self) -> "Repo":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def close(self) -> None:
        self._gix_repository = self._gix_state = None
        if self.git:
            self.git.clear_cache()
            # Tempfiles objects on Windows are holding references to open files until
            # they are collected by the garbage collector, thus preventing deletion.
            # TODO: Find these references and ensure they are closed and deleted
            # synchronously rather than forcing a gc collection.
            if sys.platform == "win32":
                gc.collect()
            gitdb.util.mman.collect()
            if sys.platform == "win32":
                gc.collect()

    def __eq__(self, rhs: object) -> bool:
        if isinstance(rhs, Repo):
            return self.git_dir == rhs.git_dir
        return False

    def __ne__(self, rhs: object) -> bool:
        return not self.__eq__(rhs)

    def __hash__(self) -> int:
        return hash(self.git_dir)

    @property
    def description(self) -> str:
        """The project's description"""
        filename = osp.join(self.git_dir, "description")
        with open(filename, "rb") as fp:
            return fp.read().rstrip().decode(defenc)

    @description.setter
    def description(self, descr: str) -> None:
        filename = osp.join(self.git_dir, "description")
        with open(filename, "wb") as fp:
            fp.write((descr + "\n").encode(defenc))

    @property
    def working_tree_dir(self) -> Optional[PathLike]:
        """
        :return:
            The working tree directory of our git repository.
            If this is a bare repository, ``None`` is returned.
        """
        return self._working_tree_dir

    @property
    def common_dir(self) -> PathLike:
        """
        :return:
            The git dir that holds everything except possibly HEAD, FETCH_HEAD,
            ORIG_HEAD, COMMIT_EDITMSG, index, and logs/.
        """
        return self._common_dir or self.git_dir

    @property
    def bare(self) -> bool:
        """:return: ``True`` if the repository is bare"""
        return self._bare

    @property
    def heads(self) -> "IterableList[Head]":
        """A list of :class:`~git.refs.head.Head` objects representing the branch heads
        in this repo.

        :return:
            ``git.IterableList(Head, ...)``
        """
        return Head.list_items(self)

    @property
    def branches(self) -> "IterableList[Head]":
        """Alias for heads.
        A list of :class:`~git.refs.head.Head` objects representing the branch heads
        in this repo.

        :return:
            ``git.IterableList(Head, ...)``
        """
        return self.heads

    @property
    def references(self) -> "IterableList[Reference]":
        """A list of :class:`~git.refs.reference.Reference` objects representing tags,
        heads and remote references.

        :return:
            ``git.IterableList(Reference, ...)``
        """
        return Reference.list_items(self)

    @property
    def refs(self) -> "IterableList[Reference]":
        """Alias for references.
        A list of :class:`~git.refs.reference.Reference` objects representing tags,
        heads and remote references.

        :return:
            ``git.IterableList(Reference, ...)``
        """
        return self.references

    @property
    def index(self) -> "IndexFile":
        """
        :return:
            A :class:`~git.index.base.IndexFile` representing this repository's index.

        :note:
            This property can be expensive, as the returned
            :class:`~git.index.base.IndexFile` will be reinitialized.
            It is recommended to reuse the object.
        """
        return IndexFile(self)

    @property
    def head(self) -> "HEAD":
        """
        :return:
            :class:`~git.refs.head.HEAD` object pointing to the current head reference
        """
        return HEAD(self, "HEAD")

    @property
    def remotes(self) -> "IterableList[Remote]":
        """A list of :class:`~git.remote.Remote` objects allowing to access and
        manipulate remotes.

        :return:
            ``git.IterableList(Remote, ...)``
        """
        return Remote.list_items(self)

    def remote(self, name: str = "origin") -> "Remote":
        """:return: The remote with the specified name

        :raise ValueError:
            If no remote with such a name exists.
        """
        r = Remote(self, name)
        if not r.exists():
            raise ValueError("Remote named '%s' didn't exist" % name)
        return r

    # { Submodules

    @property
    def submodules(self) -> "IterableList[Submodule]":
        """
        :return:
            git.IterableList(Submodule, ...) of direct submodules available from the
            current head
        """
        return Submodule.list_items(self)

    def submodule(self, name: str) -> "Submodule":
        """:return: The submodule with the given name

        :raise ValueError:
            If no such submodule exists.
        """
        try:
            return self.submodules[name]
        except IndexError as e:
            raise ValueError("Didn't find submodule named %r" % name) from e
        # END exception handling

    def create_submodule(self, *args: Any, **kwargs: Any) -> Submodule:
        """Create a new submodule.

        :note:
            For a description of the applicable parameters, see the documentation of
            :meth:`Submodule.add <git.objects.submodule.base.Submodule.add>`.

        :return:
            The created submodule.
        """
        return Submodule.add(self, *args, **kwargs)

    def iter_submodules(self, *args: Any, **kwargs: Any) -> Iterator[Submodule]:
        """An iterator yielding Submodule instances.

        See the :class:`~git.objects.util.Traversable` interface for a description of `args`
        and `kwargs`.

        :return:
            Iterator
        """
        return RootModule(self).traverse(*args, **kwargs)

    def submodule_update(self, *args: Any, **kwargs: Any) -> RootModule:
        """Update the submodules, keeping the repository consistent as it will
        take the previous state into consideration.

        :note:
            For more information, please see the documentation of
            :meth:`RootModule.update <git.objects.submodule.root.RootModule.update>`.
        """
        return RootModule(self).update(*args, **kwargs)

    # }END submodules

    @property
    def tags(self) -> "IterableList[TagReference]":
        """A list of :class:`~git.refs.tag.TagReference` objects that are available in
        this repo.

        :return:
            ``git.IterableList(TagReference, ...)``
        """
        return TagReference.list_items(self)

    def tag(self, path: PathLike) -> TagReference:
        """
        :return:
            :class:`~git.refs.tag.TagReference` object, reference pointing to a
            :class:`~git.objects.commit.Commit` or tag

        :param path:
            Path to the tag reference, e.g. ``0.1.5`` or ``tags/0.1.5``.
        """
        full_path = self._to_full_tag_path(path)
        return TagReference(self, full_path)

    @staticmethod
    def _to_full_tag_path(path: PathLike) -> str:
        path_str = str(path)
        if path_str.startswith(TagReference._common_path_default + "/"):
            return path_str
        if path_str.startswith(TagReference._common_default + "/"):
            return Reference._common_path_default + "/" + path_str
        else:
            return TagReference._common_path_default + "/" + path_str

    def create_head(
        self,
        path: PathLike,
        commit: Union["SymbolicReference", "str"] = "HEAD",
        force: bool = False,
        logmsg: Optional[str] = None,
    ) -> "Head":
        """Create a new head within the repository.

        :note:
            For more documentation, please see the
            :meth:`Head.create <git.refs.head.Head.create>` method.

        :return:
            Newly created :class:`~git.refs.head.Head` Reference.
        """
        return Head.create(self, path, commit, logmsg, force)

    def delete_head(self, *heads: "Union[str, Head]", **kwargs: Any) -> None:
        """Delete the given heads.

        :param kwargs:
            Additional keyword arguments to be passed to :manpage:`git-branch(1)`.
        """
        return Head.delete(self, *heads, **kwargs)

    def create_tag(
        self,
        path: PathLike,
        ref: Union[str, "SymbolicReference"] = "HEAD",
        message: Optional[str] = None,
        force: bool = False,
        **kwargs: Any,
    ) -> TagReference:
        """Create a new tag reference.

        :note:
            For more documentation, please see the
            :meth:`TagReference.create <git.refs.tag.TagReference.create>` method.

        :return:
            :class:`~git.refs.tag.TagReference` object
        """
        return TagReference.create(self, path, ref, message, force, **kwargs)

    def delete_tag(self, *tags: TagReference) -> None:
        """Delete the given tag references."""
        return TagReference.delete(self, *tags)

    def create_remote(self, name: str, url: str, **kwargs: Any) -> Remote:
        """Create a new remote.

        For more information, please see the documentation of the
        :meth:`Remote.create <git.remote.Remote.create>` method.

        :return:
            :class:`~git.remote.Remote` reference
        """
        return Remote.create(self, name, url, **kwargs)

    def delete_remote(self, remote: _T_RemoteName) -> _T_RemoteName:
        """Delete the given remote."""
        return Remote.remove(self, remote)

    def _get_config_path(self, config_level: Lit_config_levels, git_dir: Optional[PathLike] = None) -> str:
        if git_dir is None:
            git_dir = self.git_dir
        # We do not support an absolute path of the gitconfig on Windows.
        # Use the global config instead.
        if sys.platform == "win32" and config_level == "system":
            config_level = "global"

        if config_level == "system":
            return "/etc/gitconfig"
        elif config_level == "user":
            config_home = os.environ.get("XDG_CONFIG_HOME") or osp.join(os.environ.get("HOME", "~"), ".config")
            return osp.normpath(osp.expanduser(osp.join(config_home, "git", "config")))
        elif config_level == "global":
            return osp.normpath(osp.expanduser("~/.gitconfig"))
        elif config_level == "repository":
            repo_dir = self._common_dir or git_dir
            if not repo_dir:
                raise NotADirectoryError
            else:
                return osp.normpath(osp.join(repo_dir, "config"))
        else:
            assert_never(  # type: ignore[unreachable]
                config_level,
                ValueError(f"Invalid configuration level: {config_level!r}"),
            )

    def config_reader(
        self,
        config_level: Optional[Lit_config_levels] = None,
    ) -> GitConfigParser:
        """
        :return:
            :class:`~git.config.GitConfigParser` allowing to read the full git
            configuration, but not to write it.

            The configuration will include values from the system, user and repository
            configuration files.

        :param config_level:
            For possible values, see the :meth:`config_writer` method. If ``None``, all
            applicable levels will be used. Specify a level in case you know which file
            you wish to read to prevent reading multiple files.

        :note:
            On Windows, system configuration cannot currently be read as the path is
            unknown, instead the global path will be used.
        """
        return self._config_reader(config_level=config_level)

    def _config_reader(
        self,
        config_level: Optional[Lit_config_levels] = None,
        git_dir: Optional[PathLike] = None,
    ) -> GitConfigParser:
        if config_level is None:
            files = [self._get_config_path(f, git_dir) for f in self.config_level if f]
        else:
            files = [self._get_config_path(config_level, git_dir)]
        return GitConfigParser(files, read_only=True, repo=self)

    def config_writer(self, config_level: Lit_config_levels = "repository") -> GitConfigParser:
        """
        :return:
            A :class:`~git.config.GitConfigParser` allowing to write values of the
            specified configuration file level. Config writers should be retrieved, used
            to change the configuration, and written right away as they will lock the
            configuration file in question and prevent other's to write it.

        :param config_level:
            One of the following values:

            * ``"system"`` = system wide configuration file
            * ``"global"`` = user level configuration file
            * ``"`repository"`` = configuration file for this repository only
        """
        return GitConfigParser(self._get_config_path(config_level), read_only=False, repo=self, merge_includes=False)

    def commit(self, rev: Union[str, Commit_ish, None] = None) -> Commit:
        """The :class:`~git.objects.commit.Commit` object for the specified revision.

        :param rev:
            Revision specifier, see :manpage:`git-rev-parse(1)` for viable options.

        :return:
            :class:`~git.objects.commit.Commit`
        """
        if rev is None:
            return self.head.commit
        return to_commit(self.rev_parse(str(rev)))

    def iter_trees(self, *args: Any, **kwargs: Any) -> Iterator["Tree"]:
        """:return: Iterator yielding :class:`~git.objects.tree.Tree` objects

        :note:
            Accepts all arguments known to the :meth:`iter_commits` method.
        """
        return (c.tree for c in self.iter_commits(*args, **kwargs))

    def tree(self, rev: Union[Tree_ish, str, None] = None) -> "Tree":
        """The :class:`~git.objects.tree.Tree` object for the given tree-ish revision.

        Examples::

              repo.tree(repo.heads[0])

        :param rev:
            A revision pointing to a Treeish (being a commit or tree).

        :return:
            :class:`~git.objects.tree.Tree`

        :note:
            If you need a non-root level tree, find it by iterating the root tree.
            Otherwise it cannot know about its path relative to the repository root and
            subsequent operations might have unexpected results.
        """
        if rev is None:
            return self.head.commit.tree
        obj = self.rev_parse(str(rev))
        if obj.type == "tree":
            obj.path = getattr(obj, "path", "")
            return obj
        return to_commit(obj).tree

    def iter_commits(
        self,
        rev: Union[str, Commit, "SymbolicReference", None] = None,
        paths: Union[PathLike, Sequence[PathLike]] = "",
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> Iterator[Commit]:
        """An iterator of :class:`~git.objects.commit.Commit` objects representing the
        history of a given ref/commit.

        :param rev:
            Revision specifier, see :manpage:`git-rev-parse(1)` for viable options.
            If ``None``, the active branch will be used.

        :param paths:
            An optional path or a list of paths. If set, only commits that include the
            path or paths will be returned.

        :param kwargs:
            Arguments to be passed to :manpage:`git-rev-list(1)`.
            Common ones are ``max_count`` and ``skip``.

        :param allow_unsafe_options:
            Allow unsafe options in the revision argument, like ``--output``.

        :note:
            To receive only commits between two named revisions, use the
            ``"revA...revB"`` revision specifier.

        :return:
            Iterator of :class:`~git.objects.commit.Commit` objects
        """
        if rev is None:
            rev = self.head.commit

        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([rev], kwargs), unsafe_options=self.unsafe_git_revision_options
            )

        return Commit.iter_items(
            self,
            rev,
            paths,
            allow_unsafe_options=allow_unsafe_options,
            **kwargs,
        )

    def merge_base(self, *rev: TBD, allow_unsafe_options: bool = False, **kwargs: Any) -> List[Commit]:
        R"""Find the closest common ancestor for the given revision
        (:class:`~git.objects.commit.Commit`\s, :class:`~git.refs.tag.Tag`\s,
        :class:`~git.refs.reference.Reference`\s, etc.).

        :param rev:
            At least two revs to find the common ancestor for.

        :param allow_unsafe_options:
            Allow unsafe options in the revision arguments, like ``--output``.

        :param kwargs:
            Additional arguments to be passed to the ``repo.git.merge_base()`` command
            which does all the work.

        :return:
            A list of :class:`~git.objects.commit.Commit` objects. If ``--all`` was
            not passed as a keyword argument, the list will have at max one
            :class:`~git.objects.commit.Commit`, or is empty if no common merge base
            exists.

        :raise ValueError:
            If fewer than two revisions are provided.

        :raise git.exc.GitCommandError:
            If git fails for a reason other than having no common merge base.
        """
        if len(rev) < 2:
            raise ValueError("Please specify at least two revs, got only %i" % len(rev))
        # END handle input

        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates(rev, kwargs), unsafe_options=self.unsafe_git_revision_options
            )

        res: List[Commit] = []
        try:
            lines: List[str] = self.git._call_process_safe(
                "merge_base", "--", *(Git._check_operand(item, "revision") for item in Git._unpack_args(rev)), **kwargs
            ).splitlines()
        except GitCommandError as err:
            if err.status != 1:
                raise
            # Status code 1 is returned if there is no merge-base.
            # (See: https://github.com/git/git/blob/v2.44.0/builtin/merge-base.c#L19)
            return res
        # END exception handling

        for line in lines:
            res.append(self.commit(line))
        # END for each merge-base

        return res

    def is_ancestor(self, ancestor_rev: Commit, rev: Commit) -> bool:
        """Check if a commit is an ancestor of another.

        :param ancestor_rev:
            Rev which should be an ancestor.

        :param rev:
            Rev to test against `ancestor_rev`.

        :return:
            ``True`` if `ancestor_rev` is an ancestor to `rev`.
        """
        try:
            self.git._call_process_safe(
                "merge_base",
                "--is-ancestor",
                "--",
                Git._check_operand(ancestor_rev, "revision"),
                Git._check_operand(rev, "revision"),
            )
        except GitCommandError as err:
            if err.status == 1:
                return False
            raise
        return True

    def is_valid_object(self, sha: str, object_type: Union[str, None] = None) -> bool:
        try:
            complete_sha = self.odb.partial_to_complete_sha_hex(sha)
            object_info = self.odb.info(complete_sha)
            if object_type:
                if object_info.type == object_type.encode():
                    return True
                else:
                    _logger.debug(
                        "Commit hash points to an object of type '%s'. Requested were objects of type '%s'",
                        object_info.type.decode(),
                        object_type,
                    )
                    return False
            else:
                return True
        except BadObject:
            _logger.debug("Commit hash is invalid.")
            return False

    def _get_daemon_export(self) -> bool:
        git_dir = getattr(self, "git_dir", None)
        if git_dir is None:
            return False
        filename = osp.join(git_dir, self.DAEMON_EXPORT_FILE)
        return osp.exists(filename)

    def _set_daemon_export(self, value: object) -> None:
        git_dir = getattr(self, "git_dir", None)
        if git_dir is None:
            return
        filename = osp.join(git_dir, self.DAEMON_EXPORT_FILE)
        fileexists = osp.exists(filename)
        if value and not fileexists:
            touch(filename)
        elif not value and fileexists:
            os.unlink(filename)

    @property
    def daemon_export(self) -> bool:
        """If True, git-daemon may export this repository"""
        return self._get_daemon_export()

    @daemon_export.setter
    def daemon_export(self, value: object) -> None:
        self._set_daemon_export(value)

    @property
    def alternates(self) -> List[str]:
        """Effective alternate object directories reported by Git (read-only).

        Paths are absolute and may include environment or transitive alternates.
        Configure object sharing through Git rather than editing its storage files.
        """
        from git.diff import _unquote_path

        output = self.git._call_process_safe("count_objects", "-v", stdout_as_string=False)
        paths = []
        for line in output.splitlines():
            if line.startswith(b"alternate: "):
                path = line[len(b"alternate: ") :]
                if path.startswith(b'"') and path.endswith(b'"'):
                    path = _unquote_path(path[1:-1])
                paths.append(safe_decode(path))
        return paths

    def is_dirty(
        self,
        index: bool = True,
        working_tree: bool = True,
        untracked_files: bool = False,
        submodules: bool = True,
        path: Optional[PathLike] = None,
    ) -> bool:
        """
        :return:
            ``True`` if the repository is considered dirty. By default it will react
            like a :manpage:`git-status(1)` without untracked files, hence it is dirty
            if the index or the working copy have changes.
        """
        if self._bare:
            # Bare repositories with no associated working directory are
            # always considered to be clean.
            return False

        native = _backend.is_dirty(self.git, index, working_tree, untracked_files, submodules, path)
        if native is not NotImplemented:
            return native

        # Start from the one which is fastest to evaluate.
        default_args = ["--raw", "--no-ext-diff", "--no-textconv"]
        if not submodules:
            default_args.append("--ignore-submodules")
        if path:
            default_args.extend(["--", os.fspath(path)])
        if index:
            # diff index against HEAD.
            if self.git._call_process_safe("diff", "--cached", *default_args):
                return True
        # END index handling
        if working_tree:
            # diff index against working tree.
            if self.git._call_process_safe("diff", *default_args):
                return True
        # END working tree handling
        if untracked_files:
            if len(self._get_untracked_files(path, ignore_submodules=not submodules)):
                return True
        # END untracked files
        return False

    @property
    def untracked_files(self) -> List[str]:
        """
        :return:
            list(str,...)

            Files currently untracked as they have not been staged yet. Paths are
            relative to the current working directory of the git command.

        :note:
            Ignored files will not appear here, i.e. files mentioned in ``.gitignore``.

        :note:
            This property is expensive, as no cache is involved. To process the result,
            please consider caching it yourself.
        """
        return self._get_untracked_files()

    def _get_untracked_files(self, *args: Any, **kwargs: Any) -> List[str]:
        native = _backend.untracked_files(self.git, args, kwargs)
        if native is not NotImplemented:
            return native
        # NUL records preserve arbitrary filenames, including newlines and quotes.
        output = self.git._call_process_safe(
            "status", "--porcelain=v1", "-z", "--untracked-files=all", "--", *args, stdout_as_string=False, **kwargs
        )
        records = iter(output.split(b"\0"))
        paths = []
        for record in records:
            if record.startswith(b"?? "):
                paths.append(safe_decode(record[3:]))
            elif record[:1] in (b"R", b"C") or record[1:2] in (b"R", b"C"):
                next(records, None)  # Renames/copies carry a second path record.
        return paths

    def ignored(self, *paths: PathLike) -> List[str]:
        """Return the given paths ignored by Git, preserving their exact names."""
        paths = tuple(Git._unpack_args(paths))
        if not paths:
            return []
        for path in paths:
            if "\0" in os.fspath(path):
                raise ValueError("Paths cannot contain NUL")
        native = _backend.ignored(self.git, paths)
        if native is not NotImplemented:
            return native
        with tempfile.TemporaryFile() as stream:
            stream.write(b"\0".join(os.fspath(path).encode(defenc, "surrogateescape") for path in paths) + b"\0")
            stream.seek(0)
            status, output, stderr = self.git._call_process_safe(
                "check_ignore",
                "--stdin",
                "-z",
                istream=stream,
                stdout_as_string=False,
                with_extended_output=True,
                with_exceptions=False,
            )
        if status == 1:
            return []
        if status:
            raise GitCommandError("git check-ignore", status, stderr, output)
        return [safe_decode(path) for path in output.split(b"\0") if path]

    @property
    def active_branch(self) -> Head:
        """The currently active branch.

        Check ``repo.head.is_detached`` before accessing this property if HEAD
        may be detached. To access the current commit in either state, use
        ``repo.head.commit`` instead.

        :raise TypeError:
            If HEAD is detached.

        :raise ValueError:
            If HEAD points to an invalid reference name.

        :return:
            :class:`~git.refs.head.Head` to the active branch
        """
        return cast(Head, self.head.reference)

    def blame_incremental(
        self, rev: str | HEAD | None, file: str, allow_unsafe_options: bool = False, **kwargs: Any
    ) -> Iterator["BlameEntry"]:
        """Iterator for blame information for the given file at the given revision.

        Unlike :meth:`blame`, this does not return the actual file's contents, only a
        stream of :class:`BlameEntry` tuples.

        :param rev:
            Revision specifier. If ``None``, the blame will include all the latest
            uncommitted changes. Otherwise, anything successfully parsed by
            :manpage:`git-rev-parse(1)` is a valid option.

        :param allow_unsafe_options:
            Allow unsafe options in revision argument, like ``--output`` or ``--contents``.

        :return:
            Lazy iterator of :class:`BlameEntry` tuples, where the commit indicates the
            commit to blame for the line, and range indicates a span of line numbers in
            the resulting file.

        If you combine all line number ranges outputted by this command, you should get
        a continuous range spanning all line numbers in the file.
        """
        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([rev], kwargs),
                unsafe_options=self.unsafe_git_blame_options,
                clusterable_short_options="46bceflnpqstvw",
            )

        data: bytes = self.git._call_process_safe(
            "blame",
            Git._check_operand(rev, "revision") if rev is not None else None,
            "--no-textconv" if not allow_unsafe_options else None,
            "--",
            file,
            p=True,
            incremental=True,
            stdout_as_string=False,
            **kwargs,
        )
        commits: Dict[bytes, Commit] = {}

        stream = (line for line in data.split(b"\n") if line)
        while True:
            try:
                # When exhausted, causes a StopIteration, terminating this function.
                line = next(stream)
            except StopIteration:
                return
            split_line = line.split()
            hexsha, orig_lineno_b, lineno_b, num_lines_b = split_line
            lineno = int(lineno_b)
            num_lines = int(num_lines_b)
            orig_lineno = int(orig_lineno_b)
            if hexsha not in commits:
                # Now read the next few lines and build up a dict of properties for this
                # commit.
                props: Dict[bytes, bytes] = {}
                while True:
                    try:
                        line = next(stream)
                    except StopIteration:
                        return
                    if line == b"boundary":
                        # "boundary" indicates a root commit and occurs instead of the
                        # "previous" tag.
                        continue

                    tag, value = line.split(b" ", 1)
                    props[tag] = value
                    if tag == b"filename":
                        # "filename" formally terminates the entry for --incremental.
                        orig_filename = value
                        break

                c = Commit(
                    self,
                    hex_to_bin(hexsha),
                    author=Actor(
                        safe_decode(props[b"author"]),
                        safe_decode(props[b"author-mail"].lstrip(b"<").rstrip(b">")),
                    ),
                    authored_date=int(props[b"author-time"]),
                    committer=Actor(
                        safe_decode(props[b"committer"]),
                        safe_decode(props[b"committer-mail"].lstrip(b"<").rstrip(b">")),
                    ),
                    committed_date=int(props[b"committer-time"]),
                )
                commits[hexsha] = c
            else:
                # Discard all lines until we find "filename" which is guaranteed to be
                # the last line.
                while True:
                    try:
                        # Will fail if we reach the EOF unexpectedly.
                        line = next(stream)
                    except StopIteration:
                        return
                    tag, value = line.split(b" ", 1)
                    if tag == b"filename":
                        orig_filename = value
                        break

            yield BlameEntry(
                commits[hexsha],
                range(lineno, lineno + num_lines),
                safe_decode(orig_filename),
                range(orig_lineno, orig_lineno + num_lines),
            )

    def blame(
        self,
        rev: Union[str, HEAD, None],
        file: str,
        incremental: bool = False,
        rev_opts: Optional[Sequence[str]] = None,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> List[List[Commit | List[str | bytes] | None]] | Iterator[BlameEntry] | None:
        """The blame information for the given file at the given revision.

        :param rev:
            Revision specifier. If ``None``, the blame will include all the latest
            uncommitted changes. Otherwise, anything successfully parsed by
            :manpage:`git-rev-parse(1)` is a valid option.

        :param allow_unsafe_options:
            Allow unsafe options in revision argument, like ``--output`` or ``--contents``.

        :return:
            list: [git.Commit, list: [<line>]]

            A list of lists associating a :class:`~git.objects.commit.Commit` object
            with a list of lines that changed within the given commit. The
            :class:`~git.objects.commit.Commit` objects will be given in order of
            appearance.
        """
        if incremental:
            return self.blame_incremental(rev, file, allow_unsafe_options=allow_unsafe_options, **kwargs)
        rev_opts_list = list(rev_opts or [])
        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([rev, rev_opts_list], kwargs),
                unsafe_options=self.unsafe_git_blame_options,
                clusterable_short_options="46bceflnpqstvw",
            )
        data: bytes = self.git._call_process_safe(
            "blame",
            Git._check_operand(rev, "revision") if rev is not None else None,
            *rev_opts_list,
            "--no-textconv" if not allow_unsafe_options else None,
            "--",
            file,
            p=True,
            stdout_as_string=False,
            **kwargs,
        )
        commits: Dict[str, Commit] = {}
        blames: List[List[Commit | List[str | bytes] | None]] = []

        class InfoTD(TypedDict, total=False):
            sha: str
            id: str
            filename: str
            summary: str
            author: str
            author_email: str
            author_date: int
            committer: str
            committer_email: str
            committer_date: int

        info: InfoTD = {}

        keepends = True
        for line_bytes in data.splitlines(keepends):
            line_str = ""
            try:
                line_str = line_bytes.rstrip().decode(defenc)
            except UnicodeDecodeError:
                firstpart = ""
                parts = []
                is_binary = True
            else:
                # As we don't have an idea when the binary data ends, as it could
                # contain multiple newlines in the process. So we rely on being able to
                # decode to tell us what it is. This can absolutely fail even on text
                # files, but even if it does, we should be fine treating it as binary
                # instead.
                parts = self.re_whitespace.split(line_str, 1)
                firstpart = parts[0]
                is_binary = False
            # END handle decode of line

            if self.re_hexsha_only.search(firstpart):
                # handles
                # 634396b2f541a9f2d58b00be1a07f0c358b999b3 1 1 7        - indicates blame-data start
                # 634396b2f541a9f2d58b00be1a07f0c358b999b3 2 2          - indicates
                # another line of blame with the same data
                digits = parts[-1].split(" ")
                if len(digits) == 3:
                    info = {"id": firstpart}
                    blames.append([None, []])
                elif info["id"] != firstpart:
                    info = {"id": firstpart}
                    blames.append([commits.get(firstpart), []])
                # END blame data initialization
            else:
                m = self.re_author_committer_start.search(firstpart)
                if m:
                    # handles:
                    # author Tom Preston-Werner
                    # author-mail <tom@mojombo.com>
                    # author-time 1192271832
                    # author-tz -0700
                    # committer Tom Preston-Werner
                    # committer-mail <tom@mojombo.com>
                    # committer-time 1192271832
                    # committer-tz -0700  - IGNORED BY US
                    role = m.group(0)
                    if role == "author":
                        if firstpart.endswith("-mail"):
                            info["author_email"] = parts[-1]
                        elif firstpart.endswith("-time"):
                            info["author_date"] = int(parts[-1])
                        elif role == firstpart:
                            info["author"] = parts[-1]
                    elif role == "committer":
                        if firstpart.endswith("-mail"):
                            info["committer_email"] = parts[-1]
                        elif firstpart.endswith("-time"):
                            info["committer_date"] = int(parts[-1])
                        elif role == firstpart:
                            info["committer"] = parts[-1]
                    # END distinguish mail,time,name
                else:
                    # handle
                    # filename lib/grit.rb
                    # summary add Blob
                    # <and rest>
                    if firstpart.startswith("filename"):
                        info["filename"] = parts[-1]
                    elif firstpart.startswith("summary"):
                        info["summary"] = parts[-1]
                    elif firstpart == "":
                        if info:
                            sha = info["id"]
                            c = commits.get(sha)
                            if c is None:
                                c = Commit(
                                    self,
                                    hex_to_bin(sha),
                                    author=Actor._from_string(f"{info['author']} {info['author_email']}"),
                                    authored_date=info["author_date"],
                                    committer=Actor._from_string(f"{info['committer']} {info['committer_email']}"),
                                    committed_date=info["committer_date"],
                                )
                                commits[sha] = c
                            blames[-1][0] = c
                            # END if commit objects needs initial creation

                            if blames[-1][1] is not None:
                                line: str | bytes
                                if not is_binary:
                                    if line_str and line_str[0] == "\t":
                                        line_str = line_str[1:]
                                    line = line_str
                                else:
                                    line = line_bytes
                                    # NOTE: We are actually parsing lines out of binary
                                    # data, which can lead to the binary being split up
                                    # along the newline separator. We will append this
                                    # to the blame we are currently looking at, even
                                    # though it should be concatenated with the last
                                    # line we have seen.
                                blames[-1][1].append(line)

                            info = {"id": sha}
                        # END if we collected commit info
                    # END distinguish filename,summary,rest
                # END distinguish author|committer vs filename,summary,rest
            # END distinguish hexsha vs other information
        return blames

    @classmethod
    def init(
        cls,
        path: Union[PathLike, None] = None,
        mkdir: bool = True,
        odbt: Type[Union[GitCmdObjectDB, LooseObjectDB, gitdb.GitDB]] = GitCmdObjectDB,
        expand_vars: bool = True,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> "Repo":
        """Initialize a git repository at the given path if specified.

        :param path:
            The full path to the repo (traditionally ends with ``/<name>.git``). Or
            ``None``, in which case the repository will be created in the current
            working directory.

        :param mkdir:
            If specified, will create the repository directory if it doesn't already
            exist. Creates the directory with a mode=0755.
            Only effective if a path is explicitly given.

        :param odbt:
            Object DataBase type - a type which is constructed by providing the
            directory containing the database objects, i.e. ``.git/objects``. It will be
            used to access all object data. The pure-Python ``GitDB`` backend is
            deprecated; use the default :class:`~git.db.GitCmdObjectDB` instead.

        :param expand_vars:
            If specified, environment variables will not be escaped. This can lead to
            information disclosure, allowing attackers to access the contents of
            environment variables.

        :param allow_unsafe_options:
            Allow unsafe options to be used, such as ``--template`` and
            ``--separate-git-dir``.

        :param kwargs:
            Keyword arguments serving as additional options to the
            :manpage:`git-init(1)` command.

        :return:
            :class:`Repo` (the newly created repo)
        """
        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([], kwargs),
                unsafe_options=cls.unsafe_git_init_options,
            )
        cls.GitCommandWrapperType()._require_version()
        if path:
            path = expand_path(path, expand_vars)
        if mkdir and path and not osp.exists(path):
            os.makedirs(path, 0o755)

        # git command automatically chdir into the directory
        git = cls.GitCommandWrapperType(path)
        git._call_process_safe("init", **kwargs)
        return cls(path, odbt=odbt)

    @classmethod
    def _clone(
        cls,
        git: "Git",
        url: PathLike,
        path: PathLike,
        odb_default_type: Type[Union[GitCmdObjectDB, LooseObjectDB, gitdb.GitDB]],
        progress: Union["RemoteProgress", "UpdateProgress", Callable[..., "RemoteProgress"], None] = None,
        multi_options: Optional[List[str]] = None,
        allow_unsafe_protocols: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> "Repo":
        odbt = kwargs.pop("odbt", odb_default_type)

        # A clone creates a different repository. Do not inherit the source
        # repository's storage paths, including paths bound by Repo.__init__.
        storage_environment = {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
        }
        clone_git = cls.GitCommandWrapperType(git.working_dir)
        clone_git.update_environment(
            **{key: value for key, value in git.environment().items() if key not in storage_environment}
        )
        git = clone_git

        # url may be a path and this has no effect if it is a string
        url = os.fspath(url)
        path = os.fspath(path)

        ## A bug win cygwin's Git, when `--bare` or `--separate-git-dir`
        #  it prepends the cwd or(?) the `url` into the `path, so::
        #        git clone --bare  /cygwin/d/foo.git  C:\\Work
        #  becomes::
        #        git clone --bare  /cygwin/d/foo.git  /cygwin/d/C:\\Work
        #
        clone_path = Git.polish_url(path) if Git.is_cygwin() and "bare" in kwargs else path
        sep_dir = kwargs.get("separate_git_dir")
        if sep_dir:
            kwargs["separate_git_dir"] = Git.polish_url(os.fspath(sep_dir), expand_vars=False)
        multi = None
        if multi_options:
            multi = shlex.split(" ".join(multi_options))

        clone_url = Git.polish_url(url, expand_vars=False)
        if not allow_unsafe_protocols:
            Git.check_unsafe_protocols(clone_url)
        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([], kwargs),
                unsafe_options=cls.unsafe_git_clone_options,
            )
        if not allow_unsafe_options and multi:
            Git.check_unsafe_options(options=multi, unsafe_options=cls.unsafe_git_clone_options)

        clone_environment = dict(kwargs.pop("env", {}) or {})
        for name in storage_environment:
            clone_environment.setdefault(name, None)
        proc = git._call_process_safe(
            "clone",
            multi,
            "--",
            clone_url,
            clone_path,
            with_extended_output=True,
            as_process=True,
            v=True,
            universal_newlines=True,
            env=clone_environment,
            _allow_network=True,
            **add_progress(kwargs, git, progress),
        )
        if progress:
            handle_process_output(
                proc,
                None,
                to_progress_instance(progress).new_message_handler(),
                finalize_process,
                decode_streams=False,
            )
        else:
            (stdout, stderr) = proc.communicate()
            cmdline = getattr(proc, "args", "")
            cmdline = remove_password_if_present(cmdline)

            _logger.debug("Cmd(%s)'s unused stdout: %s", cmdline, stdout)
            finalize_process(proc, stderr=stderr)

        # Our git command could have a different working dir than our actual
        # environment, hence we prepend its working dir if required.
        if not osp.isabs(path):
            path = osp.join(git._working_dir, path) if git._working_dir is not None else path

        repo = cls(path, odbt=odbt, _env={**git.environment(), **clone_environment})

        # Adjust remotes - there may be operating systems which use backslashes, These
        # might be given as initial paths, but when handling the config file that
        # contains the remote from which we were clones, git stops liking it as it will
        # escape the backslashes. Hence we undo the escaping just to be sure.
        if repo.remotes:
            with repo.remotes[0].config_writer as writer:
                writer.set_value("url", Git.polish_url(repo.remotes[0].url, expand_vars=False))
        # END handle remote repo
        return repo

    def clone(
        self,
        path: PathLike,
        progress: Optional[CallableProgress] = None,
        multi_options: Optional[List[str]] = None,
        allow_unsafe_protocols: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> "Repo":
        """Create a clone from this repository.

        :param path:
            The full path of the new repo (traditionally ends with ``./<name>.git``).

        :param progress:
            See :meth:`Remote.push <git.remote.Remote.push>`.

        :param multi_options:
            A list of :manpage:`git-clone(1)` options that can be provided multiple
            times.

            One option per list item which is passed exactly as specified to clone.
            For example::

                [
                    "--config core.filemode=false",
                    "--config core.ignorecase",
                    "--recurse-submodule=repo1_path",
                    "--recurse-submodule=repo2_path",
                ]

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used, like ``ext``.

        :param allow_unsafe_options:
            Allow unsafe options to be used, like ``--upload-pack``.

        :param kwargs:
            * ``odbt`` = ObjectDatabase Type, allowing to determine the object database
              implementation used by the returned :class:`Repo` instance. The
              pure-Python ``GitDB`` backend is deprecated; use the default
              :class:`~git.db.GitCmdObjectDB` instead.
            * All remaining keyword arguments are given to the :manpage:`git-clone(1)`
              command.

        :return:
            :class:`Repo` (the newly cloned repo)
        """
        return self._clone(
            self.git,
            self.common_dir,
            path,
            type(self.odb),
            progress,  # type: ignore[arg-type]
            multi_options,
            allow_unsafe_protocols=allow_unsafe_protocols,
            allow_unsafe_options=allow_unsafe_options,
            **kwargs,
        )

    @classmethod
    def clone_from(
        cls,
        url: PathLike,
        to_path: PathLike,
        progress: CallableProgress = None,
        env: Optional[Mapping[str, str]] = None,
        multi_options: Optional[List[str]] = None,
        allow_unsafe_protocols: bool = False,
        allow_unsafe_options: bool = False,
        **kwargs: Any,
    ) -> "Repo":
        """Create a clone from the given URL.

        :param url:
            Valid git url, see: https://git-scm.com/docs/git-clone#URLS

        :param to_path:
            Path to which the repository should be cloned to.

        :param progress:
            See :meth:`Remote.push <git.remote.Remote.push>`.

        :param env:
            Optional dictionary containing the desired environment variables.

            Note: Provided variables will be used to update the execution environment
            for ``git``. If some variable is not specified in `env` and is defined in
            :attr:`os.environ`, value from :attr:`os.environ` will be used. If you want
            to unset some variable, consider providing empty string as its value.

        :param multi_options:
            See the :meth:`clone` method.

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used, like ``ext``.

        :param allow_unsafe_options:
            Allow unsafe options to be used, like ``--upload-pack``.

        :param kwargs:
            See the :meth:`clone` method.

        :return:
            :class:`Repo` instance pointing to the cloned directory.
        """
        git = cls.GitCommandWrapperType(os.getcwd())
        if env is not None:
            git.update_environment(**env)
        return cls._clone(
            git,
            url,
            to_path,
            GitCmdObjectDB,
            progress,  # type: ignore[arg-type]
            multi_options,
            allow_unsafe_protocols=allow_unsafe_protocols,
            allow_unsafe_options=allow_unsafe_options,
            **kwargs,
        )

    def archive(
        self,
        ostream: Union[TextIO, BinaryIO],
        treeish: Union[str, Commit, None] = None,
        prefix: Optional[str] = None,
        allow_unsafe_options: bool = False,
        allow_unsafe_protocols: bool = False,
        **kwargs: Any,
    ) -> Repo:
        """Archive the tree at the given revision.

        :param ostream:
            File-compatible stream object to which the archive will be written as bytes.

        :param treeish:
            The treeish name/id, defaults to active branch.

        :param prefix:
            The optional prefix to prepend to each filename in the archive.

        :param kwargs:
            Additional arguments passed to :manpage:`git-archive(1)`:

            * Use the ``format`` argument to define the kind of format. Use specialized
              ostreams to write any format supported by Python.
            * You may specify the special ``path`` keyword, which may either be a
              repository-relative path to a directory or file to place into the archive,
              or a list or tuple of multiple paths.

        :param allow_unsafe_options:
            Allow unsafe options, like ``--exec`` or ``--output``, and configured
            archive format commands. Otherwise only Git's built-in formats are used.

        :param allow_unsafe_protocols:
            Allow unsafe protocols to be used in ``remote``, like ``ext``.

        :raise git.exc.GitCommandError:
            If something went wrong.

        :return:
            self
        """
        if treeish is None:
            treeish = self.head.commit
        if prefix and "prefix" not in kwargs:
            kwargs["prefix"] = prefix
        if not allow_unsafe_protocols:
            # Check the emitted URL, including repeated values and Git's long-option
            # abbreviations, rather than only the untransformed `remote` keyword.
            for arg in self.git.transform_kwargs(**kwargs):
                option, separator, remote = arg.partition("=")
                if separator and option.startswith("--r") and "--remote".startswith(option):
                    Git.check_unsafe_protocols(remote)
        if not allow_unsafe_options:
            Git.check_unsafe_options(
                options=Git._option_candidates([], kwargs),
                unsafe_options=self.unsafe_git_archive_options,
            )
            for arg in self.git.transform_kwargs(**kwargs):
                option, separator, archive_format = arg.partition("=")
                if option.startswith("--f") and "--format".startswith(option):
                    if not separator or archive_format not in ("tar", "zip", "tgz", "tar.gz"):
                        raise UnsafeOptionError("Custom archive formats require allow_unsafe_options=True")
        kwargs["output_stream"] = ostream
        path = kwargs.pop("path", [])
        path = cast(Union[PathLike, List[PathLike], Tuple[PathLike, ...]], path)
        if not isinstance(path, (tuple, list)):
            path = [path]
        # END ensure paths is list (or tuple)
        self.git._call_process_safe(
            "archive",
            "--",
            Git._check_operand(treeish, "revision"),
            *path,
            _allow_network=bool(kwargs.get("remote")),
            _config=()
            if allow_unsafe_options
            else ("tar.tgz.command=git archive gzip", "tar.tar.gz.command=git archive gzip"),
            **kwargs,
        )
        return self

    def has_separate_working_tree(self) -> bool:
        """
        :return:
            True if our :attr:`git_dir` is not at the root of our
            :attr:`working_tree_dir`, but a ``.git`` file with a platform-agnostic
            symbolic link. Our :attr:`git_dir` will be wherever the ``.git`` file points
            to.

        :note:
            Bare repositories will always return ``False`` here.
        """
        if self.bare:
            return False
        if self.working_tree_dir:
            return osp.isfile(osp.join(self.working_tree_dir, ".git"))
        else:
            return False  # Or raise Error?

    rev_parse = rev_parse

    def __repr__(self) -> str:
        clazz = self.__class__
        return "<%s.%s %r>" % (clazz.__module__, clazz.__name__, self.git_dir)

    def currently_rebasing_on(self) -> Commit | None:
        """
        :return:
            The commit which is currently being replayed while rebasing.

            ``None`` if we are not currently rebasing.
        """
        if not self.git_dir:
            return None
        status, oid, stderr = self.git._call_process_safe(
            "rev_parse", "--verify", "--quiet", "REBASE_HEAD", with_extended_output=True, with_exceptions=False
        )
        if status == 1:
            return None
        if status:
            raise GitCommandError("git rev-parse", status, stderr, oid)
        return self.commit(oid)
