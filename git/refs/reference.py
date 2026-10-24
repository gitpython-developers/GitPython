# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

__all__ = ["Reference"]

import os
from git.util import IterableObj, LazyMixin

from .symbolic import SymbolicReference, T_References

# typing ------------------------------------------------------------------

from typing import Any, Callable, Iterator, TYPE_CHECKING, Type, Union

from git.types import AnyGitObject, PathLike, _T

if TYPE_CHECKING:
    from git.repo import Repo

# ------------------------------------------------------------------------------

# { Utilities


def require_remote_ref_path(func: Callable[..., _T]) -> Callable[..., _T]:
    """A decorator raising :exc:`ValueError` if we are not a valid remote, based on the
    path."""

    def wrapper(self: SymbolicReference, *args: Any) -> _T:
        if not self.is_remote():
            raise ValueError("ref path does not point to a remote reference: %s" % self.path)
        return func(self, *args)

    # END wrapper
    wrapper.__name__ = func.__name__
    return wrapper


# } END utilities


class Reference(SymbolicReference, LazyMixin, IterableObj):
    """A named reference to any object.

    Subclasses may apply restrictions though, e.g., a :class:`~git.refs.head.Head` can
    only point to commits.
    """

    __slots__ = ()

    _points_to_commits_only = False
    _resolve_ref_on_create = True
    _common_path_default = "refs"

    def __init__(self, repo: "Repo", path: PathLike, check_path: bool = True) -> None:
        """Initialize this instance.

        :param repo:
            Our parent repository.

        :param path:
            Path relative to the ``.git/`` directory pointing to the ref in question,
            e.g. ``refs/heads/master``.

        :param check_path:
            If ``False``, you can provide any path.
            Otherwise the path must start with the default path prefix of this type.
        """
        if check_path and not os.fspath(path).startswith(self._common_path_default + "/"):
            raise ValueError(f"Cannot instantiate {self.__class__.__name__!r} from path {path}")
        self.path: str  # SymbolicReference converts to string at the moment.
        super().__init__(repo, path)

    def __str__(self) -> str:
        return self.name

    # { Interface

    # @ReservedAssignment
    def set_object(
        self,
        object: Union[AnyGitObject, "SymbolicReference", str],
        logmsg: Union[str, None] = None,
    ) -> "Reference":
        """Update the reference, letting Git maintain the associated HEAD reflog."""
        super().set_object(object, logmsg)
        return self

    # NOTE: No need to overwrite properties, as the will only work without a the log.

    @property
    def name(self) -> str:
        """
        :return:
            (shortest) Name of this reference - it may contain path components
        """
        # The first two path tokens can be removed as they are
        # refs/heads or refs/tags or refs/remotes.
        tokens = self.path.split("/")
        if len(tokens) < 3:
            return self.path  # could be refs/HEAD
        return "/".join(tokens[2:])

    @classmethod
    def iter_items(
        cls: Type[T_References],
        repo: "Repo",
        common_path: Union[PathLike, None] = None,
        *args: Any,
        **kwargs: Any,
    ) -> Iterator[T_References]:
        """Equivalent to
        :meth:`SymbolicReference.iter_items <git.refs.symbolic.SymbolicReference.iter_items>`,
        but will return non-detached references as well."""
        return cls._iter_items(repo, common_path)

    # } END interface

    # { Remote Interface

    @property
    @require_remote_ref_path
    def remote_name(self) -> str:
        """
        :return:
            Name of the remote we are a reference of, such as ``origin`` for a reference
            named ``origin/master``.
        """
        tokens = self.path.split("/")
        # /refs/remotes/<remote name>/<branch_name>
        return tokens[2]

    @property
    @require_remote_ref_path
    def remote_head(self) -> str:
        """
        :return:
            Name of the remote head itself, e.g. ``master``.

        :note:
            The returned name is usually not qualified enough to uniquely identify a
            branch.
        """
        tokens = self.path.split("/")
        return "/".join(tokens[3:])

    # } END remote interface
