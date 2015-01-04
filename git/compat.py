#-*-coding:utf-8-*-
# config.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""utilities to help provide compatibility with python 3"""
# flake8: noqa

from gitdb.utils.compat import (
    PY3,
    xrange,
    MAXSIZE,
    izip,
)

from gitdb.utils.encoding import (
    string_types,
    text_type
)

if PY3:
    import io
    FileType = io.IOBase
else:
    FileType = file
