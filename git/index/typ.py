# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Additional types used by the index."""

__all__ = ["BlobFilter", "BaseIndexEntry", "IndexEntry", "StageType"]

from binascii import b2a_hex
from pathlib import Path

from git.objects import Blob
from git.objects.base import IndexObject


# typing ----------------------------------------------------------------------

from typing import NamedTuple, Sequence, TYPE_CHECKING, Tuple, Type, TypeVar, Union

from git.types import PathLike

if TYPE_CHECKING:
    from git.repo import Repo

StageType = int
_T_IndexEntry = TypeVar("_T_IndexEntry", bound="BaseIndexEntry")

# ---------------------------------------------------------------------------------

# { Invariants
CE_NAMEMASK = 0x0FFF
CE_STAGEMASK = 0x3000
CE_EXTENDED = 0x4000
CE_VALID = 0x8000
CE_STAGESHIFT = 12

CE_EXT_SKIP_WORKTREE = 0x4000
CE_EXT_INTENT_TO_ADD = 0x2000

# } END invariants


class BlobFilter:
    """Predicate to be used by
    :meth:`IndexFile.iter_blobs <git.index.base.IndexFile.iter_blobs>` allowing to
    filter only return blobs which match the given list of directories or files.

    The given paths are given relative to the repository.
    """

    __slots__ = ("paths",)

    def __init__(self, paths: Sequence[PathLike]) -> None:
        """
        :param paths:
            Tuple or list of paths which are either pointing to directories or to files
            relative to the current repository.
        """
        self.paths = paths

    def __call__(self, stage_blob: Tuple[StageType, Blob]) -> bool:
        blob_pathlike: PathLike = stage_blob[1].path
        blob_path: Path = blob_pathlike if isinstance(blob_pathlike, Path) else Path(blob_pathlike)
        for pathlike in self.paths:
            path: Path = pathlike if isinstance(pathlike, Path) else Path(pathlike)
            # TODO: Change to use `PosixPath.is_relative_to` once Python 3.8 is no
            # longer supported.
            filter_parts = path.parts
            blob_parts = blob_path.parts
            if len(filter_parts) > len(blob_parts):
                continue
            if all(i == j for i, j in zip(filter_parts, blob_parts)):
                return True
        return False


class BaseIndexEntryHelper(NamedTuple):
    """Typed named tuple to provide named attribute access for :class:`BaseIndexEntry`.

    This is needed to allow overriding ``__new__`` in child class to preserve backwards
    compatibility.
    """

    mode: int
    binsha: bytes
    flags: int
    path: PathLike


class BaseIndexEntry(BaseIndexEntryHelper):
    R"""Small brother of an index entry which can be created to describe changes
    done to the index in which case plenty of additional information is not required.

    As the first 4 data members match exactly to the :class:`IndexEntry` type, methods
    expecting a :class:`BaseIndexEntry` can also handle full :class:`IndexEntry`\s even
    if they use numeric indices for performance reasons.
    """

    def __new__(
        cls: Type[_T_IndexEntry],
        inp_tuple: Union[
            Tuple[int, bytes, int, PathLike],
            Tuple[int, bytes, int, PathLike, bytes, bytes, int, int, int, int, int],
            Tuple[int, bytes, int, PathLike, bytes, bytes, int, int, int, int, int, int],
        ],
    ) -> _T_IndexEntry:
        """Override ``__new__`` to allow construction from a tuple for backwards
        compatibility."""
        if len(inp_tuple) != 4:
            raise TypeError("Index entries contain mode, object ID, flags and path; raw stat metadata is unsupported")
        return BaseIndexEntryHelper.__new__(cls, *inp_tuple)

    def __str__(self) -> str:
        return "%o %s %i\t%s" % (self.mode, self.hexsha, self.stage, self.path)

    def __repr__(self) -> str:
        return "(%o, %s, %i, %s)" % (self.mode, self.hexsha, self.stage, self.path)

    @property
    def hexsha(self) -> str:
        """hex version of our sha"""
        return b2a_hex(self.binsha).decode("ascii")

    @property
    def stage(self) -> int:
        """Stage of the entry, either:

            * 0 = default stage
            * 1 = stage before a merge or common ancestor entry in case of a 3 way merge
            * 2 = stage of entries from the 'left' side of the merge
            * 3 = stage of entries from the 'right' side of the merge

        :note:
            For more information, see :manpage:`git-read-tree(1)`.
        """
        return (self.flags & CE_STAGEMASK) >> CE_STAGESHIFT

    @property
    def skip_worktree(self) -> bool:
        return bool(self.flags & (CE_EXT_SKIP_WORKTREE << 16))

    @classmethod
    def from_blob(cls: Type[_T_IndexEntry], blob: IndexObject, stage: int = 0) -> _T_IndexEntry:
        """:return: Fully equipped BaseIndexEntry at the given stage"""
        return cls((blob.mode, blob.binsha, stage << CE_STAGESHIFT, blob.path))

    def to_blob(self, repo: "Repo") -> Blob:
        """:return: Blob using the information of this index entry"""
        return Blob(repo, self.binsha, self.mode, self.path)


class IndexEntry(BaseIndexEntry):
    """Semantic index entry. Git owns filesystem cache metadata and extensions."""

    @classmethod
    def from_base(cls, base: BaseIndexEntry) -> "IndexEntry":
        return cls((base.mode, base.binsha, base.flags, base.path))
