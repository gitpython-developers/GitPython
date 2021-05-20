# util.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Module for general utility functions"""

from git.util import (
    IterableList,
    Actor
)

import re
from collections import deque

from string import digits
import time
import calendar
from datetime import datetime, timedelta, tzinfo

# typing ------------------------------------------------------------
from typing import (Any, Callable, Deque, Iterator, Sequence, TYPE_CHECKING, Tuple, Type, Union, cast, overload)

if TYPE_CHECKING:
    from io import BytesIO, StringIO
    from .submodule.base import Submodule
    from .commit import Commit
    from .blob import Blob
    from .tag import TagObject
    from .tree import Tree
    from subprocess import Popen

# --------------------------------------------------------------------

__all__ = ('get_object_type_by_name', 'parse_date', 'parse_actor_and_date',
           'ProcessStreamAdapter', 'Traversable', 'altz_to_utctz_str', 'utctz_to_altz',
           'verify_utctz', 'Actor', 'tzoffset', 'utc')

ZERO = timedelta(0)

#{ Functions


def mode_str_to_int(modestr: Union[bytes, str]) -> int:
    """
    :param modestr: string like 755 or 644 or 100644 - only the last 6 chars will be used
    :return:
        String identifying a mode compatible to the mode methods ids of the
        stat module regarding the rwx permissions for user, group and other,
        special flags and file system flags, i.e. whether it is a symlink
        for example."""
    mode = 0
    for iteration, char in enumerate(reversed(modestr[-6:])):
        char = cast(Union[str, int], char)
        mode += int(char) << iteration * 3
    # END for each char
    return mode


def get_object_type_by_name(object_type_name: bytes
                            ) -> Union[Type['Commit'], Type['TagObject'], Type['Tree'], Type['Blob']]:
    """
    :return: type suitable to handle the given object type name.
        Use the type to create new instances.

    :param object_type_name: Member of TYPES

    :raise ValueError: In case object_type_name is unknown"""
    if object_type_name == b"commit":
        from . import commit
        return commit.Commit
    elif object_type_name == b"tag":
        from . import tag
        return tag.TagObject
    elif object_type_name == b"blob":
        from . import blob
        return blob.Blob
    elif object_type_name == b"tree":
        from . import tree
        return tree.Tree
    else:
        raise ValueError("Cannot handle unknown object type: %s" % object_type_name.decode())


def utctz_to_altz(utctz: str) -> int:
    """we convert utctz to the timezone in seconds, it is the format time.altzone
    returns. Git stores it as UTC timezone which has the opposite sign as well,
    which explains the -1 * ( that was made explicit here )
    :param utctz: git utc timezone string, i.e. +0200"""
    return -1 * int(float(utctz) / 100 * 3600)


def altz_to_utctz_str(altz: int) -> str:
    """As above, but inverses the operation, returning a string that can be used
    in commit objects"""
    utci = -1 * int((float(altz) / 3600) * 100)
    utcs = str(abs(utci))
    utcs = "0" * (4 - len(utcs)) + utcs
    prefix = (utci < 0 and '-') or '+'
    return prefix + utcs


def verify_utctz(offset: str) -> str:
    """:raise ValueError: if offset is incorrect
    :return: offset"""
    fmt_exc = ValueError("Invalid timezone offset format: %s" % offset)
    if len(offset) != 5:
        raise fmt_exc
    if offset[0] not in "+-":
        raise fmt_exc
    if offset[1] not in digits or\
       offset[2] not in digits or\
       offset[3] not in digits or\
       offset[4] not in digits:
        raise fmt_exc
    # END for each char
    return offset


class tzoffset(tzinfo):

    def __init__(self, secs_west_of_utc: float, name: Union[None, str] = None) -> None:
        self._offset = timedelta(seconds=-secs_west_of_utc)
        self._name = name or 'fixed'

    def __reduce__(self) -> Tuple[Type['tzoffset'], Tuple[float, str]]:
        return tzoffset, (-self._offset.total_seconds(), self._name)

    def utcoffset(self, dt) -> timedelta:
        return self._offset

    def tzname(self, dt) -> str:
        return self._name

    def dst(self, dt) -> timedelta:
        return ZERO


utc = tzoffset(0, 'UTC')


def from_timestamp(timestamp, tz_offset: float) -> datetime:
    """Converts a timestamp + tz_offset into an aware datetime instance."""
    utc_dt = datetime.fromtimestamp(timestamp, utc)
    try:
        local_dt = utc_dt.astimezone(tzoffset(tz_offset))
        return local_dt
    except ValueError:
        return utc_dt


def parse_date(string_date: str) -> Tuple[int, int]:
    """
    Parse the given date as one of the following

        * aware datetime instance
        * Git internal format: timestamp offset
        * RFC 2822: Thu, 07 Apr 2005 22:13:13 +0200.
        * ISO 8601 2005-04-07T22:13:13
            The T can be a space as well

    :return: Tuple(int(timestamp_UTC), int(offset)), both in seconds since epoch
    :raise ValueError: If the format could not be understood
    :note: Date can also be YYYY.MM.DD, MM/DD/YYYY and DD.MM.YYYY.
    """
    if isinstance(string_date, datetime) and string_date.tzinfo:
        offset = -int(string_date.utcoffset().total_seconds())
        return int(string_date.astimezone(utc).timestamp()), offset

    # git time
    try:
        if string_date.count(' ') == 1 and string_date.rfind(':') == -1:
            timestamp, offset_str = string_date.split()
            if timestamp.startswith('@'):
                timestamp = timestamp[1:]
            timestamp_int = int(timestamp)
            return timestamp_int, utctz_to_altz(verify_utctz(offset_str))
        else:
            offset_str = "+0000"                    # local time by default
            if string_date[-5] in '-+':
                offset_str = verify_utctz(string_date[-5:])
                string_date = string_date[:-6]  # skip space as well
            # END split timezone info
            offset = utctz_to_altz(offset_str)

            # now figure out the date and time portion - split time
            date_formats = []
            splitter = -1
            if ',' in string_date:
                date_formats.append("%a, %d %b %Y")
                splitter = string_date.rfind(' ')
            else:
                # iso plus additional
                date_formats.append("%Y-%m-%d")
                date_formats.append("%Y.%m.%d")
                date_formats.append("%m/%d/%Y")
                date_formats.append("%d.%m.%Y")

                splitter = string_date.rfind('T')
                if splitter == -1:
                    splitter = string_date.rfind(' ')
                # END handle 'T' and ' '
            # END handle rfc or iso

            assert splitter > -1

            # split date and time
            time_part = string_date[splitter + 1:]    # skip space
            date_part = string_date[:splitter]

            # parse time
            tstruct = time.strptime(time_part, "%H:%M:%S")

            for fmt in date_formats:
                try:
                    dtstruct = time.strptime(date_part, fmt)
                    utctime = calendar.timegm((dtstruct.tm_year, dtstruct.tm_mon, dtstruct.tm_mday,
                                               tstruct.tm_hour, tstruct.tm_min, tstruct.tm_sec,
                                               dtstruct.tm_wday, dtstruct.tm_yday, tstruct.tm_isdst))
                    return int(utctime), offset
                except ValueError:
                    continue
                # END exception handling
            # END for each fmt

            # still here ? fail
            raise ValueError("no format matched")
        # END handle format
    except Exception as e:
        raise ValueError("Unsupported date format: %s" % string_date) from e
    # END handle exceptions


# precompiled regex
_re_actor_epoch = re.compile(r'^.+? (.*) (\d+) ([+-]\d+).*$')
_re_only_actor = re.compile(r'^.+? (.*)$')


def parse_actor_and_date(line: str) -> Tuple[Actor, int, int]:
    """Parse out the actor (author or committer) info from a line like::

        author Tom Preston-Werner <tom@mojombo.com> 1191999972 -0700

    :return: [Actor, int_seconds_since_epoch, int_timezone_offset]"""
    actor, epoch, offset = '', '0', '0'
    m = _re_actor_epoch.search(line)
    if m:
        actor, epoch, offset = m.groups()
    else:
        m = _re_only_actor.search(line)
        actor = m.group(1) if m else line or ''
    return (Actor._from_string(actor), int(epoch), utctz_to_altz(offset))

#} END functions


#{ Classes

class ProcessStreamAdapter(object):

    """Class wireing all calls to the contained Process instance.

    Use this type to hide the underlying process to provide access only to a specified
    stream. The process is usually wrapped into an AutoInterrupt class to kill
    it if the instance goes out of scope."""
    __slots__ = ("_proc", "_stream")

    def __init__(self, process: 'Popen', stream_name: str) -> None:
        self._proc = process
        self._stream = getattr(process, stream_name)  # type: StringIO  ## guess

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._stream, attr)


class Traversable(object):

    """Simple interface to perform depth-first or breadth-first traversals
    into one direction.
    Subclasses only need to implement one function.
    Instances of the Subclass must be hashable

    Defined subclasses = [Commit, Tree, SubModule]
    """
    __slots__ = ()

    @overload
    @classmethod
    def _get_intermediate_items(cls, item: 'Commit') -> Tuple['Commit', ...]:
        ...

    @overload
    @classmethod
    def _get_intermediate_items(cls, item: 'Submodule') -> Tuple['Submodule', ...]:
        ...

    @overload
    @classmethod
    def _get_intermediate_items(cls, item: 'Tree') -> Tuple['Tree', ...]:
        ...

    @overload
    @classmethod
    def _get_intermediate_items(cls, item: 'Traversable') -> Tuple['Traversable', ...]:
        ...

    @classmethod
    def _get_intermediate_items(cls, item: 'Traversable'
                                ) -> Sequence['Traversable']:
        """
        Returns:
            Tuple of items connected to the given item.
            Must be implemented in subclass

        class Commit::     (cls, Commit) -> Tuple[Commit, ...]
        class Submodule::  (cls, Submodule) -> Iterablelist[Submodule]
        class Tree::       (cls, Tree) -> Tuple[Tree, ...]
        """
        raise NotImplementedError("To be implemented in subclass")

    def list_traverse(self, *args: Any, **kwargs: Any) -> IterableList:
        """
        :return: IterableList with the results of the traversal as produced by
            traverse()"""
        out = IterableList(self._id_attribute_)  # type: ignore[attr-defined]  # defined in sublcasses
        out.extend(self.traverse(*args, **kwargs))
        return out

    def traverse(self,
                 predicate: Callable[[object, int], bool] = lambda i, d: True,
                 prune: Callable[[object, int], bool] = lambda i, d: False,
                 depth: int = -1,
                 branch_first: bool = True,
                 visit_once: bool = True, ignore_self: int = 1, as_edge: bool = False
                 ) -> Union[Iterator['Traversable'], Iterator[Tuple['Traversable', 'Traversable']]]:
        """:return: iterator yielding of items found when traversing self

        :param predicate: f(i,d) returns False if item i at depth d should not be included in the result

        :param prune:
            f(i,d) return True if the search should stop at item i at depth d.
            Item i will not be returned.

        :param depth:
            define at which level the iteration should not go deeper
            if -1, there is no limit
            if 0, you would effectively only get self, the root of the iteration
            i.e. if 1, you would only get the first level of predecessors/successors

        :param branch_first:
            if True, items will be returned branch first, otherwise depth first

        :param visit_once:
            if True, items will only be returned once, although they might be encountered
            several times. Loops are prevented that way.

        :param ignore_self:
            if True, self will be ignored and automatically pruned from
            the result. Otherwise it will be the first item to be returned.
            If as_edge is True, the source of the first edge is None

        :param as_edge:
            if True, return a pair of items, first being the source, second the
            destination, i.e. tuple(src, dest) with the edge spanning from
            source to destination"""
        visited = set()
        stack = deque()  # type: Deque[Tuple[int, Traversable, Union[Traversable, None]]]
        stack.append((0, self, None))       # self is always depth level 0

        def addToStack(stack: Deque[Tuple[int, 'Traversable', Union['Traversable', None]]],
                       item: 'Traversable',
                       branch_first: bool,
                       depth) -> None:
            lst = self._get_intermediate_items(item)
            if not lst:
                return None
            if branch_first:
                stack.extendleft((depth, i, item) for i in lst)
            else:
                reviter = ((depth, lst[i], item) for i in range(len(lst) - 1, -1, -1))
                stack.extend(reviter)
        # END addToStack local method

        while stack:
            d, item, src = stack.pop()          # depth of item, item, item_source

            if visit_once and item in visited:
                continue

            if visit_once:
                visited.add(item)

            rval = (as_edge and (src, item)) or item
            if prune(rval, d):
                continue

            skipStartItem = ignore_self and (item is self)
            if not skipStartItem and predicate(rval, d):
                yield rval

            # only continue to next level if this is appropriate !
            nd = d + 1
            if depth > -1 and nd > depth:
                continue

            addToStack(stack, item, branch_first, nd)
        # END for each item on work stack


class Serializable(object):

    """Defines methods to serialize and deserialize objects from and into a data stream"""
    __slots__ = ()

    def _serialize(self, stream: 'BytesIO') -> 'Serializable':
        """Serialize the data of this object into the given data stream
        :note: a serialized object would ``_deserialize`` into the same object
        :param stream: a file-like object
        :return: self"""
        raise NotImplementedError("To be implemented in subclass")

    def _deserialize(self, stream: 'BytesIO') -> 'Serializable':
        """Deserialize all information regarding this object from the stream
        :param stream: a file-like object
        :return: self"""
        raise NotImplementedError("To be implemented in subclass")
