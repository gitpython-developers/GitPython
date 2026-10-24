# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

__all__ = [
    "sm_section",
    "sm_name",
    "mkhead",
    "find_first_remote_branch",
    "is_relative_url",
    "resolve_relative_url",
    "SubmoduleConfigParser",
]

from io import BytesIO
import sys
import weakref

import git
from git.config import GitConfigParser
from git.exc import InvalidGitRepositoryError

# typing -----------------------------------------------------------------------

from typing import Any, Sequence, TYPE_CHECKING, Union

from git.types import PathLike

if TYPE_CHECKING:
    from weakref import ReferenceType

    from git.refs import Head, RemoteReference
    from git.remote import Remote
    from git.repo import Repo

    from .base import Submodule

# { Utilities


def sm_section(name: str) -> str:
    """:return: Section title used in ``.gitmodules`` configuration file"""
    return GitConfigParser._public_section("submodule." + name)


def sm_name(section: str) -> str:
    """:return: Name of the submodule as parsed from the section name"""
    return GitConfigParser._section_name(section.strip())[10:]


def mkhead(repo: "Repo", path: PathLike) -> "Head":
    """:return: New branch/head instance"""
    return git.Head(repo, git.Head.to_full_path(path))


def find_first_remote_branch(remotes: Sequence["Remote"], branch_name: str) -> "RemoteReference":
    """Find the remote branch matching the name of the given branch or raise
    :exc:`~git.exc.InvalidGitRepositoryError`."""
    for remote in remotes:
        try:
            return remote.refs[branch_name]
        except IndexError:
            continue
        # END exception handling
    # END for remote
    raise InvalidGitRepositoryError("Didn't find remote branch '%r' in any of the given remotes" % branch_name)


def _is_dir_sep(char: str) -> bool:
    return char == "/" or (sys.platform == "win32" and char == "\\")


def _starts_with_dot_slash(url: str) -> bool:
    return len(url) >= 2 and url[0] == "." and _is_dir_sep(url[1])


def _starts_with_dot_dot_slash(url: str) -> bool:
    return len(url) >= 3 and url[0:2] == ".." and _is_dir_sep(url[2])


def _has_dos_drive_prefix(url: str) -> bool:
    return sys.platform == "win32" and len(url) >= 2 and url[0].isalpha() and url[1] == ":"


def _is_absolute_path(url: str) -> bool:
    return (len(url) >= 1 and _is_dir_sep(url[0])) or _has_dos_drive_prefix(url)


def _url_is_local_not_ssh(url: str) -> bool:
    colon = url.find(":")
    slash = url.find("/")
    return colon == -1 or (slash != -1 and slash < colon) or _has_dos_drive_prefix(url)


def _find_last_dir_sep(url: str) -> int:
    for index in range(len(url) - 1, -1, -1):
        if _is_dir_sep(url[index]):
            return index
    return -1


def is_relative_url(url: str) -> bool:
    """:return: ``True`` if `url` starts with ``./`` or ``../``, which git resolves
    against the superproject's remote rather than treating as a path"""
    return _starts_with_dot_slash(url) or _starts_with_dot_dot_slash(url)


def resolve_relative_url(remote_url: str, url: str) -> str:
    """Resolve a submodule URL that starts with ``./`` or ``../`` against the
    superproject's remote URL, the way git's ``relative_url`` does.

    Git treats a relative submodule URL like a relative directory: each leading
    ``../`` removes the last component of `remote_url`, whether that is a path
    component, the host of a URL, or the host of an scp-like ``host:path`` address.
    The remainder is appended with ``/``, or with ``:`` once an scp-like host was
    reached. A URL that is not relative is returned unchanged.

    :raise ValueError:
        If more components are stripped than `remote_url` has, which git rejects with
        "cannot strip one component off url".
    """
    if not is_relative_url(url):
        return url

    remote = remote_url
    if remote and _is_dir_sep(remote[-1]):
        remote = remote[:-1]

    is_relative = _url_is_local_not_ssh(remote) and not _is_absolute_path(remote)
    if is_relative and not _starts_with_dot_slash(remote) and not _starts_with_dot_dot_slash(remote):
        remote = "./" + remote

    colonsep = False
    while url:
        if _starts_with_dot_dot_slash(url):
            url = url[3:]
            separator = _find_last_dir_sep(remote)
            if separator != -1:
                remote = remote[:separator]
            elif ":" in remote:
                remote = remote[: remote.rfind(":")]
                colonsep = True
            elif is_relative or remote == ".":
                raise ValueError("cannot strip one component off url %r" % remote)
            else:
                remote = "."
        elif _starts_with_dot_slash(url):
            url = url[2:]
        else:
            break

    resolved = remote + (":" if colonsep else "/") + url
    if url.endswith("/"):
        resolved = resolved[:-1]
    if _starts_with_dot_slash(resolved):
        resolved = resolved[2:]
    return resolved


# } END utilities

# { Classes


class SubmoduleConfigParser(GitConfigParser):
    """Catches calls to :meth:`~git.config.GitConfigParser.write`, and updates the
    ``.gitmodules`` blob in the index with the new data, if we have written into a
    stream.

    Otherwise it would add the local file to the index to make it correspond with the
    working tree. Additionally, the cache must be cleared.

    Please note that no mutating method will work in bare mode.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._smref: Union["ReferenceType[Submodule]", None] = None
        self._index = None
        self._auto_write = True
        super().__init__(*args, **kwargs)

    # { Interface
    def set_submodule(self, submodule: "Submodule") -> None:
        """Set this instance's submodule. It must be called before the first write
        operation begins."""
        self._smref = weakref.ref(submodule)

    def flush_to_index(self) -> None:
        """Flush changes in our configuration file to the index."""
        assert self._smref is not None
        # Should always have a file here.
        assert not isinstance(self._file_or_files, BytesIO)

        sm = self._smref()
        if sm is not None:
            index = self._index
            if index is None:
                index = sm.repo.index
            # END handle index
            index.add([sm.k_modules_file], write=self._auto_write)
            sm._clear_cache()
        # END handle weakref

    # } END interface

    # { Overridden Methods
    def write(self) -> None:
        rval: None = super().write()
        self.flush_to_index()
        return rval

    # END overridden methods


# } END classes
