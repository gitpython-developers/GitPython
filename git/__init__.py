# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

# @PydevCodeAnalysisIgnore

__version__ = "git"

from typing import List, Optional, Sequence, Tuple, Union, TYPE_CHECKING

from gitdb.util import to_hex_sha
from git.exc import *  # noqa: F403  # @NoMove @IgnorePep8
from git.types import PathLike

try:
    from git.compat import safe_decode  # @NoMove @IgnorePep8
    from git.config import GitConfigParser  # @NoMove @IgnorePep8
    from git.objects import *  # noqa: F403  # @NoMove @IgnorePep8
    from git.refs import *  # noqa: F403  # @NoMove @IgnorePep8
    from git.diff import *  # noqa: F403  # @NoMove @IgnorePep8
    from git.db import *  # noqa: F403  # @NoMove @IgnorePep8
    from git.cmd import Git  # @NoMove @IgnorePep8
    from git.repo import Repo  # @NoMove @IgnorePep8
    from git.remote import *  # noqa: F403  # @NoMove @IgnorePep8
    from git.index import *  # noqa: F403  # @NoMove @IgnorePep8
    from git.util import (  # @NoMove @IgnorePep8
        LockFile,
        BlockingLockFile,
        Stats,
        Actor,
        remove_password_if_present,
        rmtree,
    )
except GitError as _exc:  # noqa: F405
    raise ImportError("%s: %s" % (_exc.__class__.__name__, _exc)) from _exc

# __all__ must be statically defined by py.typed support
# __all__ = [name for name, obj in locals().items() if not (name.startswith("_") or inspect.ismodule(obj))]
__all__ = [  # noqa: F405
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
    "IndexEntry",
    "IndexFile",
    "IndexObject",
    "InvalidDBRoot",
    "InvalidGitRepositoryError",
    "List",
    "LockFile",
    "NULL_TREE",
    "NoSuchPathError",
    "ODBError",
    "Object",
    "Optional",
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
    "Sequence",
    "StageType",
    "Stats",
    "Submodule",
    "SymbolicReference",
    "TYPE_CHECKING",
    "Tag",
    "TagObject",
    "TagReference",
    "Tree",
    "TreeModifier",
    "Tuple",
    "Union",
    "UnmergedEntriesError",
    "UnsafeOptionError",
    "UnsafeProtocolError",
    "UnsupportedOperation",
    "UpdateProgress",
    "WorkTreeRepositoryUnsupported",
    "remove_password_if_present",
    "rmtree",
    "safe_decode",
    "to_hex_sha",
]

# { Initialize git executable path
GIT_OK = None


def refresh(path: Optional[PathLike] = None) -> None:
    """Convenience method for setting the git executable path.

    :param path: Optional path to the Git executable. If not absolute, it is resolved
        immediately, relative to the current directory.

    :note: The *path* parameter is usually omitted and cannot be used to specify a
        custom command whose location is looked up in a path search on each call. See
        :meth:`Git.refresh` for details on how to achieve this.

    :note: This calls :meth:`Git.refresh` and sets other global configuration according
        to the effect of doing so. As such, this function should usually be used instead
        of using :meth:`Git.refresh` or :meth:`FetchInfo.refresh` directly.

    :note: This function is called automatically, with no arguments, at import time.
    """
    global GIT_OK
    GIT_OK = False

    if not Git.refresh(path=path):
        return
    if not FetchInfo.refresh():  # noqa: F405
        return  # type: ignore [unreachable]

    GIT_OK = True


# } END initialize git executable path


#################
try:
    refresh()
except Exception as _exc:
    raise ImportError("Failed to initialize: {0}".format(_exc)) from _exc
#################
