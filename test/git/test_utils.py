import os
from test.testlib import *
from git_python import *

class TestUtils(object):
    def setup(self):
        base = os.path.join(os.path.dirname(__file__), "../.."),
        self.git = Git(base)
        self.git_bin_base = "%s --git-dir='%s'" % (Git.git_binary, base)

    def test_it_escapes_single_quotes_with_shell_escape(self):
        assert_equal("\\\\'foo", shell_escape("'foo"))

    def test_it_should_dashify(self):
        assert_equal('this-is-my-argument', dashify('this_is_my_argument'))
        assert_equal('foo', dashify('foo'))
