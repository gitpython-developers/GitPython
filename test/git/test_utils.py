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
