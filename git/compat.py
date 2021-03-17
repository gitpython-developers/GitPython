# -*- coding: utf-8 -*-
# config.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""utilities to help provide compatibility with python 3"""
# flake8: noqa

import locale
import os
import sys

from gitdb.utils.encoding import (
    force_bytes,     # @UnusedImport
    force_text       # @UnusedImport
)

# typing --------------------------------------------------------------------

from typing import Any, AnyStr, Dict, Optional, Type
from git.types import TBD

# ---------------------------------------------------------------------------


is_win = (os.name == 'nt')  # type: bool
is_posix = (os.name == 'posix')
is_darwin = (os.name == 'darwin')
defenc = sys.getfilesystemencoding()


def safe_decode(s: Optional[AnyStr]) -> Optional[str]:
    """Safely decodes a binary string to unicode"""
    if isinstance(s, str):
        return s
    elif isinstance(s, bytes):
        return s.decode(defenc, 'surrogateescape')
    elif s is None:
        return None
    else:
        raise TypeError('Expected bytes or text, but got %r' % (s,))


def safe_encode(s: Optional[AnyStr]) -> Optional[bytes]:
    """Safely encodes a binary string to unicode"""
    if isinstance(s, str):
        return s.encode(defenc)
    elif isinstance(s, bytes):
        return s
    elif s is None:
        return None
    else:
        raise TypeError('Expected bytes or text, but got %r' % (s,))


def win_encode(s: Optional[AnyStr]) -> Optional[bytes]:
    """Encode unicodes for process arguments on Windows."""
    if isinstance(s, str):
        return s.encode(locale.getpreferredencoding(False))
    elif isinstance(s, bytes):
        return s
    elif s is not None:
        raise TypeError('Expected bytes or text, but got %r' % (s,))
    return None



def with_metaclass(meta: Type[Any], *bases: Any) -> 'metaclass': # type: ignore ## mypy cannot understand dynamic class creation
    """copied from https://github.com/Byron/bcore/blob/master/src/python/butility/future.py#L15"""

    class metaclass(meta):  # type: ignore
        __call__ = type.__call__
        __init__ = type.__init__    # type: ignore

        def __new__(cls, name: str, nbases: Optional[int], d: Dict[str, Any]) -> TBD:
            if nbases is None:
                return type.__new__(cls, name, (), d)
            return meta(name, bases, d)

    return metaclass(meta.__name__ + 'Helper', None, {})
