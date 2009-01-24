# asserts.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import re
import unittest
from nose import tools
from nose.tools import *

__all__ = ['assert_instance_of', 'assert_not_instance_of', 
           'assert_none', 'assert_not_none',
           'assert_match', 'assert_not_match'] + tools.__all__

def assert_instance_of(expected, actual, msg=None):
    """Verify that object is an instance of expected """
    assert isinstance(actual, expected), msg

def assert_not_instance_of(expected, actual, msg=None):
    """Verify that object is not an instance of expected """
    assert not isinstance(actual, expected, msg)
    
def assert_none(actual, msg=None):
    """verify that item is None"""
    assert_equal(None, actual, msg)

def assert_not_none(actual, msg=None):
    """verify that item is None"""
    assert_not_equal(None, actual, msg)

def assert_match(pattern, string, msg=None):
    """verify that the pattern matches the string"""
    assert_not_none(re.search(pattern, string), msg)

def assert_not_match(pattern, string, msg=None):
    """verify that the pattern does not match the string"""
    assert_none(re.search(pattern, string), msg)