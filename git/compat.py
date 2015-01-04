#-*-coding:utf-8-*-
# config.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""utilities to help provide compatibility with python 3"""

from gitdb.utils.compat import (  # noqa
    PY3,
    xrange,
    MAXSIZE,
    izip,
)

from gitdb.utils.encoding import (   # noqa
    string_types,
    text_type
)
