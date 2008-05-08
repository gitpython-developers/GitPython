import os
from mock import *
from test.asserts import *
from git_python import *
from test.helper import *

class TestGit(object):
    def setup(self):
        base = os.path.join(os.path.dirname(__file__), "../.."),
        self.git = Git(base)
        self.git_bin_base = "%s --git-dir=%s" % (Git.git_binary, base)

    @patch(Git, 'execute')
    def test_method_missing_calls_execute(self, git):
        git.return_value = ''
        self.git.version()
        assert_true(git.called)
        # assert_equal(git.call_args, ((("%s version " % self.git_bin_base),), {}))
    
    def test_it_transforms_kwargs_into_git_command_arguments(self):
        assert_equal(["-s"], self.git.transform_kwargs(**{'s': True}))
        assert_equal(["-s 5"], self.git.transform_kwargs(**{'s': 5}))

        assert_equal(["--max-count"], self.git.transform_kwargs(**{'max_count': True}))
        assert_equal(["--max-count=5"], self.git.transform_kwargs(**{'max_count': 5}))
        
        assert_equal(["-s", "-t"], self.git.transform_kwargs(**{'s': True, 't': True}))

    def test_it_executes_git_to_shell_and_returns_result(self):
        assert_match('^git version [\d\.]*$', self.git.execute("%s version" % Git.git_binary))

    def test_it_transforms_kwargs_shell_escapes_arguments(self):
        assert_equal(["--foo=\"bazz'er\""], self.git.transform_kwargs(**{'foo': "bazz'er"}))
        assert_equal(["-x \"bazz'er\""], self.git.transform_kwargs(**{'x': "bazz'er"}))

    @patch(Git, 'execute')
    def test_it_really_shell_escapes_arguments_to_the_git_shell_1(self, git):
        self.git.foo(**{'bar': "bazz'er"})
        assert_true(git.called)
        assert_equal(git.call_args, ((("%s foo --bar=\"bazz'er\"" % self.git_bin_base),), {}))

    @patch(Git, 'execute')
    def test_it_really_shell_escapes_arguments_to_the_git_shell_2(self, git):
        self.git.bar(**{'x': "quu'x"})
        assert_true(git.called)
        assert_equal(git.call_args, ((("%s bar -x \"quu'x\"" % self.git_bin_base),), {}))

    def test_it_shell_escapes_the_standalone_argument(self):
        self.git.foo("bar's", {})
