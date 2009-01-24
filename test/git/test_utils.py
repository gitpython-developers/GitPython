# test_utils.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
from test.testlib import *
from git import *

class TestUtils(object):
    def setup(self):
        self.testdict = {
            "string":   "42",
            "int":      42,
            "array":    [ 42 ],
        }

    def test_it_should_dashify(self):
        assert_equal('this-is-my-argument', dashify('this_is_my_argument'))
        assert_equal('foo', dashify('foo'))
