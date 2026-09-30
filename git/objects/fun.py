# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Functions that are supposed to be as fast as possible."""

__all__ = [
    "tree_to_stream",
    "tree_entries_from_data",
    "traverse_trees_recursive",
    "traverse_tree_recursive",
]

from stat import S_ISDIR

from git.compat import safe_decode, defenc
from git.util import _validate_repo_path

# typing ----------------------------------------------

from typing import (
    Callable,
    List,
    MutableSequence,
    Sequence,
    Tuple,
    TYPE_CHECKING,
    Union,
    overload,
)

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer

    from gitdb.db.base import ObjectDBR

EntryTup = Tuple[bytes, int, str]  # Same as TreeCacheTup in tree.py.
EntryTupOrNone = Union[EntryTup, None]

# ---------------------------------------------------


def _validate_tree_entry_name(name: str) -> None:
    if "/" in name:
        raise ValueError("Tree entry names must not contain '/' characters")
    # A tree name is a component, not a rooted path; a colon cannot select a drive.
    _validate_repo_path("tree/" + name)


def tree_to_stream(entries: Sequence[EntryTup], write: Callable[["ReadableBuffer"], Union[int, None]]) -> None:
    """Write the given list of entries into a stream using its ``write`` method.

    :param entries:
        **Sorted** list of tuples with (binsha, mode, name).

    :param write:
        A ``write`` method which takes a data string.
    """
    ord_zero = ord("0")
    bit_mask = 7  # 3 bits set.

    for binsha, mode, name in entries:
        if len(binsha) != 20:
            raise ValueError("Tree entry object IDs must be exactly 20 bytes")
        if mode >> 12 not in (4, 8, 10, 14):
            raise ValueError("Invalid tree entry mode")
        mode_str = b""
        for i in range(6):
            mode_str = bytes([((mode >> (i * 3)) & bit_mask) + ord_zero]) + mode_str
        # END for each 8 octal value

        # git slices away the first octal if it's zero.
        if mode_str[0] == ord_zero:
            mode_str = mode_str[1:]
        # END save a byte

        # Here it comes: If the name is actually unicode, the replacement below will not
        # work as the binsha is not part of the ascii unicode encoding - hence we must
        # convert to an UTF-8 string for it to work properly. According to my tests,
        # this is exactly what git does, that is it just takes the input literally,
        # which appears to be UTF-8 on linux.
        if isinstance(name, str):
            name_bytes = name.encode(defenc)
        else:
            name_bytes = name  # type: ignore[unreachable]  # check runtime types - is always str?
        _validate_tree_entry_name(safe_decode(name_bytes))
        write(b"".join((mode_str, b" ", name_bytes, b"\0", binsha)))
    # END for each item


def tree_entries_from_data(data: bytes) -> List[EntryTup]:
    """Read complete tree records, rejecting invalid names and truncated fields.

    :param data:
        Data block with tree data (as bytes).

    :return:
        list(tuple(binsha, mode, tree_relative_path), ...)
    """
    out = []
    offset = 0
    while offset < len(data):
        mode_end = data.find(b" ", offset)
        if mode_end < 0:
            raise ValueError("Unterminated tree entry mode")
        mode_bytes = data[offset:mode_end]
        if not mode_bytes or mode_bytes.strip(b"01234567"):
            raise ValueError("Invalid tree entry mode")
        mode = int(mode_bytes, 8)
        if mode >> 12 not in (4, 8, 10, 14):
            raise ValueError("Invalid tree entry mode")
        name_end = data.find(b"\0", mode_end + 1)
        if name_end < 0 or name_end + 21 > len(data):
            raise ValueError("Truncated tree entry")
        name = safe_decode(bytes(data[mode_end + 1 : name_end]))
        _validate_tree_entry_name(name)
        offset = name_end + 21
        out.append((bytes(data[name_end + 1 : offset]), mode, name))
    return out


def _find_by_name(tree_data: MutableSequence[EntryTupOrNone], name: str, is_dir: bool, start_at: int) -> EntryTupOrNone:
    """Return data entry matching the given name and tree mode or ``None``.

    Before the item is returned, the respective data item is set None in the `tree_data`
    list to mark it done.
    """

    try:
        item = tree_data[start_at]
        if item and item[2] == name and S_ISDIR(item[1]) == is_dir:
            tree_data[start_at] = None
            return item
    except IndexError:
        pass
    # END exception handling
    for index, item in enumerate(tree_data):
        if item and item[2] == name and S_ISDIR(item[1]) == is_dir:
            tree_data[index] = None
            return item
        # END if item matches
    # END for each item
    return None


@overload
def _to_full_path(item: None, path_prefix: str) -> None: ...


@overload
def _to_full_path(item: EntryTup, path_prefix: str) -> EntryTup: ...


def _to_full_path(item: EntryTupOrNone, path_prefix: str) -> EntryTupOrNone:
    """Rebuild entry with given path prefix."""
    if not item:
        return item
    return (item[0], item[1], path_prefix + item[2])


def traverse_trees_recursive(
    odb: "ObjectDBR", tree_shas: Sequence[Union[bytes, None]], path_prefix: str
) -> List[Tuple[EntryTupOrNone, ...]]:
    """
    :return:
        List of list with entries according to the given binary tree-shas.

        The result is encoded in a list
        of n tuple|None per blob/commit, (n == len(tree_shas)), where:

        * [0] == 20 byte sha
        * [1] == mode as int
        * [2] == path relative to working tree root

        The entry tuple is ``None`` if the respective blob/commit did not exist in the
        given tree.

    :param tree_shas:
        Iterable of shas pointing to trees. All trees must be on the same level.
        A tree-sha may be ``None``, in which case ``None``.

    :param path_prefix:
        A prefix to be added to the returned paths on this level.
        Set it ``""`` for the first iteration.

    :note:
        The ordering of the returned items will be partially lost.
    """
    trees_data: List[List[EntryTupOrNone]] = []

    nt = len(tree_shas)
    for tree_sha in tree_shas:
        if tree_sha is None:
            data: List[EntryTupOrNone] = []
        else:
            # Make new list for typing as list invariant.
            data = list(tree_entries_from_data(odb.stream(tree_sha).read()))
        # END handle muted trees
        trees_data.append(data)
    # END for each sha to get data for

    out: List[Tuple[EntryTupOrNone, ...]] = []

    # Find all matching entries and recursively process them together if the match is a
    # tree. If the match is a non-tree item, put it into the result.
    # Processed items will be set None.
    for ti, tree_data in enumerate(trees_data):
        for ii, item in enumerate(tree_data):
            if not item:
                continue
            # END skip already done items
            entries: List[EntryTupOrNone]
            entries = [None for _ in range(nt)]
            entries[ti] = item
            _sha, mode, name = item
            is_dir = S_ISDIR(mode)  # Type mode bits

            # Find this item in all other tree data items.
            # Wrap around, but stop one before our current index, hence ti+nt, not
            # ti+1+nt.
            for tio in range(ti + 1, ti + nt):
                tio = tio % nt
                entries[tio] = _find_by_name(trees_data[tio], name, is_dir, ii)

            # END for each other item data
            # If we are a directory, enter recursion.
            if is_dir:
                out.extend(
                    traverse_trees_recursive(
                        odb,
                        [((ei and ei[0]) or None) for ei in entries],
                        path_prefix + name + "/",
                    )
                )
            else:
                out.append(tuple(_to_full_path(e, path_prefix) for e in entries))

            # END handle recursion
            # Finally mark it done.
            tree_data[ii] = None
        # END for each item

        # We are done with one tree, set all its data empty.
        del tree_data[:]
    # END for each tree_data chunk
    return out


def traverse_tree_recursive(odb: "ObjectDBR", tree_sha: bytes, path_prefix: str) -> List[EntryTup]:
    """
    :return:
        List of entries of the tree pointed to by the binary `tree_sha`.

        An entry has the following format:

        * [0] 20 byte sha
        * [1] mode as int
        * [2] path relative to the repository

    :param path_prefix:
        Prefix to prepend to the front of all returned paths.
    """
    entries = []
    data = tree_entries_from_data(odb.stream(tree_sha).read())

    # Unpacking/packing is faster than accessing individual items.
    for sha, mode, name in data:
        if S_ISDIR(mode):
            entries.extend(traverse_tree_recursive(odb, sha, path_prefix + name + "/"))
        else:
            entries.append((sha, mode, path_prefix + name))
    # END for each item

    return entries
