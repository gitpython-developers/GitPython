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

from gitdb.utils.compat import (
    xrange,
    MAXSIZE,    # @UnusedImport
    izip,       # @UnusedImport
)
from gitdb.utils.encoding import (
    string_types,    # @UnusedImport
    text_type,       # @UnusedImport
    force_bytes,     # @UnusedImport
    force_text       # @UnusedImport
)


PY3 = sys.version_info[0] >= 3
is_win = (os.name == 'nt')
is_posix = (os.name == 'posix')
is_darwin = (os.name == 'darwin')
defenc = sys.getdefaultencoding()

if PY3:
    import io
    FileType = io.IOBase

    def byte_ord(b):
        return b

    def bchr(n):
        return bytes([n])

    def mviter(d):
        return d.values()

    range = xrange  # @ReservedAssignment
    unicode = str
    binary_type = bytes
else:
    FileType = file  # @UndefinedVariable on PY3
    # usually, this is just ascii, which might not enough for our encoding needs
    # Unless it's set specifically, we override it to be utf-8
    if defenc == 'ascii':
        defenc = 'utf-8'
    byte_ord = ord
    bchr = chr
    unicode = unicode
    binary_type = str
    range = xrange  # @ReservedAssignment

    def mviter(d):
        return d.itervalues()


def safe_decode(s):
    """Safely decodes a binary string to unicode"""
    if isinstance(s, unicode):
        return s
    elif isinstance(s, bytes):
        return s.decode(defenc, 'replace')
    elif s is not None:
        raise TypeError('Expected bytes or text, but got %r' % (s,))


def safe_encode(s):
    """Safely decodes a binary string to unicode"""
    if isinstance(s, unicode):
        return s.encode(defenc)
    elif isinstance(s, bytes):
        return s
    elif s is not None:
        raise TypeError('Expected bytes or text, but got %r' % (s,))


def win_encode(s):
    """Encode unicodes for process arguments on Windows."""
    if isinstance(s, unicode):
        return s.encode(locale.getpreferredencoding(False))
    elif isinstance(s, bytes):
        return s
    elif s is not None:
        raise TypeError('Expected bytes or text, but got %r' % (s,))


def with_metaclass(meta, *bases):
    """copied from https://github.com/Byron/bcore/blob/master/src/python/butility/future.py#L15"""
    class metaclass(meta):
        __call__ = type.__call__
        __init__ = type.__init__

        def __new__(cls, name, nbases, d):
            if nbases is None:
                return type.__new__(cls, name, (), d)
            # There may be clients who rely on this attribute to be set to a reasonable value, which is why
            # we set the __metaclass__ attribute explicitly
            if not PY3 and '___metaclass__' not in d:
                d['__metaclass__'] = meta
            return meta(name, bases, d)
    return metaclass(meta.__name__ + 'Helper', None, {})


## From https://docs.python.org/3.3/howto/pyporting.html
class UnicodeMixin(object):

    """Mixin class to handle defining the proper __str__/__unicode__
    methods in Python 2 or 3."""

    if PY3:
        def __str__(self):
            return self.__unicode__()
    else:  # Python 2
        def __str__(self):
            return self.__unicode__().encode(defenc)
