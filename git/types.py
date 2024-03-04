# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import os
import sys
from typing import (  # noqa: F401
    Dict,
    NoReturn,
    Sequence as Sequence,
    Tuple,
    Union,
    Any,
    Optional,
    Callable,
    TYPE_CHECKING,
    TypeVar,
)

if sys.version_info >= (3, 8):
    from typing import (  # noqa: F401
        Literal,
        TypedDict,
        Protocol,
        SupportsIndex as SupportsIndex,
        runtime_checkable,
    )
else:
    from typing_extensions import (  # noqa: F401
        Literal,
        SupportsIndex as SupportsIndex,
        TypedDict,
        Protocol,
        runtime_checkable,
    )

# if sys.version_info >= (3, 10):
#     from typing import TypeGuard  # noqa: F401
# else:
#     from typing_extensions import TypeGuard  # noqa: F401

PathLike = Union[str, "os.PathLike[str]"]
"""A :class:`str` (Unicode) based file or directory path."""

if TYPE_CHECKING:
    from git.repo import Repo
    from git.objects import Commit, Tree, TagObject, Blob

TBD = Any
"""Alias of :class:`~typing.Any`, when a type hint is meant to become more specific."""

_T = TypeVar("_T")
"""Type variable used internally in GitPython."""

Tree_ish = Union["Commit", "Tree"]
"""Union of :class:`~git.objects.base.Object`-based types that are inherently tree-ish.

See gitglossary(7) on "tree-ish": https://git-scm.com/docs/gitglossary#def_tree-ish

:note:
    This union comprises **only** the :class:`~git.objects.commit.Commit` and
    :class:`~git.objects.tree.Tree` classes, **all** of whose instances are tree-ish.
    This is done because of the way GitPython uses it as a static type annotation.

    :class:`~git.objects.tag.TagObject`, some but not all of whose instances are
    tree-ish (those representing git tag objects that ultimately resolve to a tree or
    commit), is not covered as part of this union type.
"""

Commit_ish = Union["Commit", "TagObject", "Blob", "Tree"]
"""Union of the :class:`~git.objects.base.Object`-based types that represent kinds of
git objects. This union is often usable where a commit-ish is expected, but is not
actually limited to types representing commit-ish git objects.

See gitglossary(7) on:

* "commit-ish": https://git-scm.com/docs/gitglossary#def_commit-ish
* "object type": https://git-scm.com/docs/gitglossary#def_object_type

:note:
    This union comprises **more** classes than those whose instances really represent
    commit-ish git objects:

    * A :class:`~git.objects.commit.Commit` is of course always commit-ish, and a
      :class:`~git.objects.tag.TagObject` is commit-ish if, when peeled (recursively
      followed), a :class:`~git.objects.commit.Commit` is obtained.
    * However, :class:`~git.objects.blob.Blob` and :class:`~git.objects.tree.Tree` are
      also included, and they represent git objects that are never really commit-ish.

    This is an inversion of the situation with :class:`Tree_ish`, which is narrower than
    all tree-ish objects. It is done for practical reasons including backward
    compatibility.
"""

Lit_commit_ish = Literal["commit", "tag", "blob", "tree"]
"""Literal strings identifying concrete :class:`~git.objects.base.Object` subtypes
representing kinds of git objects.

See the :class:`Object.type <git.objects.base.Object.type>` attribute.

:note:
    See also :class:`Commit_ish`, a union of the the :class:`~git.objects.base.Object`
    subtypes associated with these literal strings.

:note:
    As noted in :class:`Commit_ish`, this is not limited to types of git objects that
    are actually commit-ish.
"""

# Config_levels ---------------------------------------------------------

Lit_config_levels = Literal["system", "global", "user", "repository"]
"""Type of literal strings naming git configuration levels.

Such a string identifies what level, or scope, a git configuration variable is in.
"""

ConfigLevels_Tup = Tuple[Literal["system"], Literal["user"], Literal["global"], Literal["repository"]]
"""Static type of a tuple of the four strings representing configuration levels."""

# def is_config_level(inp: str) -> TypeGuard[Lit_config_levels]:
#     # return inp in get_args(Lit_config_level)  # only py >= 3.8
#     return inp in ("system", "user", "global", "repository")

# Progress parameter type alias -----------------------------------------

CallableProgress = Optional[Callable[[int, Union[str, float], Union[str, float, None], str], None]]
"""General type of a progress reporter for cloning.

This is the type of a function or other callable that reports the progress of a clone,
when passed as a ``progress`` argument to :meth:`Repo.clone <git.repo.base.Repo.clone>`
or :meth:`Repo.clone_from <git.repo.base.Repo.clone_from>`.
"""

# -----------------------------------------------------------------------------------


def assert_never(inp: NoReturn, raise_error: bool = True, exc: Union[Exception, None] = None) -> None:
    """For use in exhaustive checking of a literal or enum in if/else chains.

    A call to this function should only be reached if not all members are handled, or if
    an attempt is made to pass non-members through the chain.

    :param inp:
        If all members are handled, the argument for `inp` will have the
        :class:`~typing.Never`/:class:`~typing.NoReturn` type. Otherwise, the type will
        mismatch and cause a mypy error.

    :param raise_error:
        If ``True``, will also raise :class:`ValueError` with a general "unhandled
        literal" message, or the exception object passed as `exc`.

    :param exc:
        It not ``None``, this should be an already-constructed exception object, to be
        raised if `raise_error` is ``True``.
    """
    if raise_error:
        if exc is None:
            raise ValueError(f"An unhandled literal ({inp!r}) in an if/else chain was found")
        else:
            raise exc


class Files_TD(TypedDict):
    """Dictionary with stat counts for the diff of a particular file.

    For the :class:`~git.util.Stats.files` attribute of :class:`~git.util.Stats`
    objects.
    """

    insertions: int
    deletions: int
    lines: int


class Total_TD(TypedDict):
    """Dictionary with total stats from any number of files.

    For the :class:`~git.util.Stats.total` attribute of :class:`~git.util.Stats`
    objects.
    """

    insertions: int
    deletions: int
    lines: int
    files: int


class HSH_TD(TypedDict):
    """Dictionary carrying the same information as a :class:`~git.util.Stats` object."""

    total: Total_TD
    files: Dict[PathLike, Files_TD]


@runtime_checkable
class Has_Repo(Protocol):
    repo: "Repo"


@runtime_checkable
class Has_id_attribute(Protocol):
    _id_attribute_: str
