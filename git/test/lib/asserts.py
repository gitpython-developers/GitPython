# asserts.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import re
from unittest.mock import patch

from nose.tools import (
    assert_equal,       # @UnusedImport
    assert_not_equal,   # @UnusedImport
    assert_raises,      # @UnusedImport
    raises,             # @UnusedImport
    assert_true,        # @UnusedImport
    assert_false        # @UnusedImport
)

__all__ = ['assert_not_none', 'assert_match',
           'assert_equal', 'assert_not_equal', 'assert_raises', 'patch', 'raises',
           'assert_true', 'assert_false']


def assert_not_none(actual, msg=None):
    """verify that item is None"""
    assert actual is not None, msg


def assert_match(pattern, string, msg=None):
    """verify that the pattern matches the string"""
    assert_not_none(re.search(pattern, string), msg)
