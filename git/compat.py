#-*-coding:utf-8-*-
# config.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""utilities to help provide compatibility with python 3"""
# flake8: noqa

import sys

from gitdb.utils.compat import (
    PY3,
    xrange,
    MAXSIZE,
    izip,
)

from gitdb.utils.encoding import (
    string_types,
    text_type,
    force_bytes,
    force_text
)

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
    unicode = str
else:
    FileType = file
    # usually, this is just ascii, which might not enough for our encoding needs
    # Unless it's set specifically, we override it to be utf-8
    if defenc == 'ascii':
        defenc = 'utf-8'
    byte_ord = ord
    bchr = chr
    unicode = unicode
    def mviter(d):
        return d.itervalues()


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
            # end
            return meta(name, bases, d)
        # end
    # end metaclass
    return metaclass(meta.__name__ + 'Helper', None, {})
    # end handle py2
