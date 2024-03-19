# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

# @PydevCodeAnalysisIgnore

__all__ = [
    "Actor",
    "AmbiguousObjectName",
    "BadName",
    "BadObject",
    "BadObjectType",
    "BaseIndexEntry",
    "Blob",
    "BlobFilter",
    "BlockingLockFile",
    "CacheError",
    "CheckoutError",
    "CommandError",
    "Commit",
    "Diff",
    "DiffConstants",
    "DiffIndex",
    "Diffable",
    "FetchInfo",
    "Git",
    "GitCmdObjectDB",
    "GitCommandError",
    "GitCommandNotFound",
    "GitConfigParser",
    "GitDB",
    "GitError",
    "HEAD",
    "Head",
    "HookExecutionError",
    "INDEX",
    "IndexEntry",
    "IndexFile",
    "IndexObject",
    "InvalidDBRoot",
    "InvalidGitRepositoryError",
    "List",  # Deprecated - import this from `typing` instead.
    "LockFile",
    "NULL_TREE",
    "NoSuchPathError",
    "ODBError",
    "Object",
    "Optional",  # Deprecated - import this from `typing` instead.
    "ParseError",
    "PathLike",
    "PushInfo",
    "RefLog",
    "RefLogEntry",
    "Reference",
    "Remote",
    "RemoteProgress",
    "RemoteReference",
    "Repo",
    "RepositoryDirtyError",
    "RootModule",
    "RootUpdateProgress",
    "Sequence",  # Deprecated - import from `typing`, or `collections.abc` in 3.9+.
    "StageType",
    "Stats",
    "Submodule",
    "SymbolicReference",
    "TYPE_CHECKING",  # Deprecated - import this from `typing` instead.
    "Tag",
    "TagObject",
    "TagReference",
    "Tree",
    "TreeModifier",
    "Tuple",  # Deprecated - import this from `typing` instead.
    "Union",  # Deprecated - import this from `typing` instead.
    "UnmergedEntriesError",
    "UnsafeOptionError",
    "UnsafeProtocolError",
    "UnsupportedOperation",
    "UpdateProgress",
    "WorkTreeRepositoryUnsupported",
    "refresh",
    "remove_password_if_present",
    "rmtree",
    "safe_decode",
    "to_hex_sha",
]

__version__ = "git"

from typing import List, Optional, Sequence, TYPE_CHECKING, Tuple, Union

from gitdb.util import to_hex_sha

from git.exc import (
    AmbiguousObjectName,
    BadName,
    BadObject,
    BadObjectType,
    CacheError,
    CheckoutError,
    CommandError,
    GitCommandError,
    GitCommandNotFound,
    GitError,
    HookExecutionError,
    InvalidDBRoot,
    InvalidGitRepositoryError,
    NoSuchPathError,
    ODBError,
    ParseError,
    RepositoryDirtyError,
    UnmergedEntriesError,
    UnsafeOptionError,
    UnsafeProtocolError,
    UnsupportedOperation,
    WorkTreeRepositoryUnsupported,
)
from git.types import PathLike

try:
    from git.compat import safe_decode  # @NoMove
    from git.config import GitConfigParser  # @NoMove
    from git.objects import (  # @NoMove
        Blob,
        Commit,
        IndexObject,
        Object,
        RootModule,
        RootUpdateProgress,
        Submodule,
        TagObject,
        Tree,
        TreeModifier,
        UpdateProgress,
    )
    from git.refs import (  # @NoMove
        HEAD,
        Head,
        RefLog,
        RefLogEntry,
        Reference,
        RemoteReference,
        SymbolicReference,
        Tag,
        TagReference,
    )
    from git.diff import (  # @NoMove
        INDEX,
        NULL_TREE,
        Diff,
        DiffConstants,
        DiffIndex,
        Diffable,
    )
    from git.db import GitCmdObjectDB, GitDB  # @NoMove
    from git.cmd import Git  # @NoMove
    from git.repo import Repo  # @NoMove
    from git.remote import FetchInfo, PushInfo, Remote, RemoteProgress  # @NoMove
    from git.index import (  # @NoMove
        BaseIndexEntry,
        BlobFilter,
        CheckoutError,
        IndexEntry,
        IndexFile,
        StageType,
        util,  # noqa: F401  # For backward compatibility.
    )
    from git.util import (  # @NoMove
        Actor,
        BlockingLockFile,
        LockFile,
        Stats,
        remove_password_if_present,
        rmtree,
    )
except GitError as _exc:
    raise ImportError("%s: %s" % (_exc.__class__.__name__, _exc)) from _exc

# { Initialize git executable path
GIT_OK = None


def refresh(path: Optional[PathLike] = None) -> None:
    """Convenience method for setting the git executable path.

    :param path:
        Optional path to the Git executable. If not absolute, it is resolved
        immediately, relative to the current directory.

    :note:
        The `path` parameter is usually omitted and cannot be used to specify a custom
        command whose location is looked up in a path search on each call. See
        :meth:`Git.refresh <git.cmd.Git.refresh>` for details on how to achieve this.

    :note:
        This calls :meth:`Git.refresh <git.cmd.Git.refresh>` and sets other global
        configuration according to the effect of doing so. As such, this function should
        usually be used instead of using :meth:`Git.refresh <git.cmd.Git.refresh>` or
        :meth:`FetchInfo.refresh <git.remote.FetchInfo.refresh>` directly.

    :note:
        This function is called automatically, with no arguments, at import time.
    """
    global GIT_OK
    GIT_OK = False

    if not Git.refresh(path=path):
        return
    if not FetchInfo.refresh():  # noqa: F405
        return  # type: ignore[unreachable]

    GIT_OK = True


# } END initialize git executable path


#################
try:
    refresh()
except Exception as _exc:
    raise ImportError("Failed to initialize: {0}".format(_exc)) from _exc
#################
