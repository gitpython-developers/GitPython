import os
from test.testlib import *
from git_python import *

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

    def test_pop_key_array(self):
        array = pop_key(self.testdict, "array")
        assert_equal( [ 42 ], array )
        assert_equal( False, "array" in self.testdict )

    def test_pop_key_string(self):
        stringValue = pop_key(self.testdict, "string")
        assert_equal( "42", stringValue )
        assert_equal( False, "string" in self.testdict )

    def test_pop_key_int(self):
        intValue = pop_key(self.testdict, "int")
        assert_equal( 42, intValue )
        assert_equal( False, "int" in self.testdict )
