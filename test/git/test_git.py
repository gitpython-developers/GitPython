# test_git.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os, sys
from test.testlib import *
from git import Git, GitCommandError

class TestGit(object):
    def setup(self):
        base = os.path.join(os.path.dirname(__file__), "../..")
        self.git = Git(base)

    @patch_object(Git, 'execute')
    def test_call_process_calls_execute(self, git):
        git.return_value = ''
        self.git.version()
        assert_true(git.called)
        assert_equal(git.call_args, ((['git', 'version'],), {}))

    @raises(GitCommandError)
    def test_it_raises_errors(self):
        self.git.this_does_not_exist()


    def test_it_transforms_kwargs_into_git_command_arguments(self):
        assert_equal(["-s"], self.git.transform_kwargs(**{'s': True}))
        assert_equal(["-s5"], self.git.transform_kwargs(**{'s': 5}))

        assert_equal(["--max-count"], self.git.transform_kwargs(**{'max_count': True}))
        assert_equal(["--max-count=5"], self.git.transform_kwargs(**{'max_count': 5}))

        assert_equal(["-s", "-t"], self.git.transform_kwargs(**{'s': True, 't': True}))

    def test_it_executes_git_to_shell_and_returns_result(self):
        assert_match('^git version [\d\.]{2}.*$', self.git.execute(["git","version"]))

    def test_it_accepts_stdin(self):
        filename = fixture_path("cat_file_blob")
        fh = open(filename, 'r')
        assert_equal("70c379b63ffa0795fdbfbc128e5a2818397b7ef8",
                     self.git.hash_object(istream=fh, stdin=True))
        fh.close()

    def test_it_handles_large_input(self):
        if sys.platform == 'win32':
            output = self.git.execute(["type", "C:\WINDOWS\system32\cmd.exe"])
        else:
            output = self.git.execute(["cat", "/bin/bash"])
        assert_true(len(output) > 4096) # at least 4k

    @patch_object(Git, 'execute')
    def test_it_ignores_false_kwargs(self, git):
        # this_should_not_be_ignored=False implies it *should* be ignored
        output = self.git.version(pass_this_kwarg=False)
        assert_true("pass_this_kwarg" not in git.call_args[1])
