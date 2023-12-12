# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import gc
import inspect
import logging
import os
import os.path as osp
import re
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory, TemporaryFile
from unittest import skipUnless

if sys.version_info >= (3, 8):
    from unittest import mock
else:
    import mock  # To be able to examine call_args.kwargs on a mock.

import ddt

from git import Git, refresh, GitCommandError, GitCommandNotFound, Repo, cmd
from git.util import cwd, finalize_process
from test.lib import TestBase, fixture_path, with_rw_directory


@ddt.ddt
class TestGit(TestBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.git = Git(cls.rorepo.working_dir)

    def tearDown(self):
        gc.collect()

    def _assert_logged_for_popen(self, log_watcher, name, value):
        re_name = re.escape(name)
        re_value = re.escape(str(value))
        re_line = re.compile(rf"DEBUG:git.cmd:Popen\(.*\b{re_name}={re_value}[,)]")
        match_attempts = [re_line.match(message) for message in log_watcher.output]
        self.assertTrue(any(match_attempts), repr(log_watcher.output))

    @mock.patch.object(Git, "execute")
    def test_call_process_calls_execute(self, git):
        git.return_value = ""
        self.git.version()
        self.assertTrue(git.called)
        self.assertEqual(git.call_args, ((["git", "version"],), {}))

    def test_call_unpack_args_unicode(self):
        args = Git._unpack_args("Unicode€™")
        mangled_value = "Unicode\u20ac\u2122"
        self.assertEqual(args, [mangled_value])

    def test_call_unpack_args(self):
        args = Git._unpack_args(["git", "log", "--", "Unicode€™"])
        mangled_value = "Unicode\u20ac\u2122"
        self.assertEqual(args, ["git", "log", "--", mangled_value])

    def test_it_raises_errors(self):
        self.assertRaises(GitCommandError, self.git.this_does_not_exist)

    def test_it_transforms_kwargs_into_git_command_arguments(self):
        self.assertEqual(["-s"], self.git.transform_kwargs(**{"s": True}))
        self.assertEqual(["-s", "5"], self.git.transform_kwargs(**{"s": 5}))
        self.assertEqual([], self.git.transform_kwargs(**{"s": None}))

        self.assertEqual(["--max-count"], self.git.transform_kwargs(**{"max_count": True}))
        self.assertEqual(["--max-count=5"], self.git.transform_kwargs(**{"max_count": 5}))
        self.assertEqual(["--max-count=0"], self.git.transform_kwargs(**{"max_count": 0}))
        self.assertEqual([], self.git.transform_kwargs(**{"max_count": None}))

        # Multiple args are supported by using lists/tuples.
        self.assertEqual(
            ["-L", "1-3", "-L", "12-18"],
            self.git.transform_kwargs(**{"L": ("1-3", "12-18")}),
        )
        self.assertEqual(["-C", "-C"], self.git.transform_kwargs(**{"C": [True, True, None, False]}))

        # Order is undefined.
        res = self.git.transform_kwargs(**{"s": True, "t": True})
        self.assertEqual({"-s", "-t"}, set(res))

    _shell_cases = (
        # value_in_call, value_from_class, expected_popen_arg
        (None, False, False),
        (None, True, True),
        (False, True, False),
        (False, False, False),
        (True, False, True),
        (True, True, True),
    )

    def _do_shell_combo(self, value_in_call, value_from_class):
        with mock.patch.object(Git, "USE_SHELL", value_from_class):
            # git.cmd gets Popen via a "from" import, so patch it there.
            with mock.patch.object(cmd, "Popen", wraps=cmd.Popen) as mock_popen:
                # Use a command with no arguments (besides the program name), so it runs
                # with or without a shell, on all OSes, with the same effect.
                self.git.execute(["git"], with_exceptions=False, shell=value_in_call)

        return mock_popen

    @ddt.idata(_shell_cases)
    def test_it_uses_shell_or_not_as_specified(self, case):
        """A bool passed as ``shell=`` takes precedence over `Git.USE_SHELL`."""
        value_in_call, value_from_class, expected_popen_arg = case
        mock_popen = self._do_shell_combo(value_in_call, value_from_class)
        mock_popen.assert_called_once()
        self.assertIs(mock_popen.call_args.kwargs["shell"], expected_popen_arg)

    @ddt.idata(full_case[:2] for full_case in _shell_cases)
    def test_it_logs_if_it_uses_a_shell(self, case):
        """``shell=`` in the log message agrees with what is passed to `Popen`."""
        value_in_call, value_from_class = case
        with self.assertLogs(cmd.log, level=logging.DEBUG) as log_watcher:
            mock_popen = self._do_shell_combo(value_in_call, value_from_class)
        self._assert_logged_for_popen(log_watcher, "shell", mock_popen.call_args.kwargs["shell"])

    @ddt.data(
        ("None", None),
        ("<valid stream>", subprocess.PIPE),
    )
    def test_it_logs_istream_summary_for_stdin(self, case):
        expected_summary, istream_argument = case
        with self.assertLogs(cmd.log, level=logging.DEBUG) as log_watcher:
            self.git.execute(["git", "version"], istream=istream_argument)
        self._assert_logged_for_popen(log_watcher, "stdin", expected_summary)

    def test_it_executes_git_and_returns_result(self):
        self.assertRegex(self.git.execute(["git", "version"]), r"^git version [\d\.]{2}.*$")

    def test_it_executes_git_not_from_cwd(self):
        with TemporaryDirectory() as tmpdir:
            if os.name == "nt":
                # Copy an actual binary executable that is not git.
                other_exe_path = os.path.join(os.getenv("WINDIR"), "system32", "hostname.exe")
                impostor_path = os.path.join(tmpdir, "git.exe")
                shutil.copy(other_exe_path, impostor_path)
            else:
                # Create a shell script that doesn't do anything.
                impostor_path = os.path.join(tmpdir, "git")
                with open(impostor_path, mode="w", encoding="utf-8") as file:
                    print("#!/bin/sh", file=file)
                os.chmod(impostor_path, 0o755)

            with cwd(tmpdir):
                self.assertRegex(self.git.execute(["git", "version"]), r"^git version\b")

    @skipUnless(
        os.name == "nt",
        "The regression only affected Windows, and this test logic is OS-specific.",
    )
    def test_it_avoids_upcasing_unrelated_environment_variable_names(self):
        old_name = "28f425ca_d5d8_4257_b013_8d63166c8158"
        if old_name == old_name.upper():
            raise RuntimeError("test bug or strange locale: old_name invariant under upcasing")

        # Step 1: Set the environment variable in this parent process. Because os.putenv is a thin
        #         wrapper around a system API, os.environ never sees the variable in this parent
        #         process, so the name is not upcased even on Windows.
        os.putenv(old_name, "1")

        # Step 2: Create the child process that inherits the environment variable. The child uses
        #         GitPython, and we are testing that it passes the variable with the exact original
        #         name to its own child process (the grandchild).
        cmdline = [
            sys.executable,
            fixture_path("env_case.py"),  # Contains steps 3 and 4.
            self.rorepo.working_dir,
            old_name,
        ]
        pair_text = subprocess.check_output(cmdline, shell=False, text=True)  # Run steps 3 and 4.

        new_name = pair_text.split("=")[0]
        self.assertEqual(new_name, old_name)

    def test_it_accepts_stdin(self):
        filename = fixture_path("cat_file_blob")
        with open(filename, "r") as fh:
            self.assertEqual(
                "70c379b63ffa0795fdbfbc128e5a2818397b7ef8",
                self.git.hash_object(istream=fh, stdin=True),
            )

    @mock.patch.object(Git, "execute")
    def test_it_ignores_false_kwargs(self, git):
        # this_should_not_be_ignored=False implies it *should* be ignored.
        self.git.version(pass_this_kwarg=False)
        self.assertTrue("pass_this_kwarg" not in git.call_args[1])

    def test_it_raises_proper_exception_with_output_stream(self):
        tmp_file = TemporaryFile()
        self.assertRaises(
            GitCommandError,
            self.git.checkout,
            "non-existent-branch",
            output_stream=tmp_file,
        )

    def test_it_accepts_environment_variables(self):
        filename = fixture_path("ls_tree_empty")
        with open(filename, "r") as fh:
            tree = self.git.mktree(istream=fh)
            env = {
                "GIT_AUTHOR_NAME": "Author Name",
                "GIT_AUTHOR_EMAIL": "author@example.com",
                "GIT_AUTHOR_DATE": "1400000000+0000",
                "GIT_COMMITTER_NAME": "Committer Name",
                "GIT_COMMITTER_EMAIL": "committer@example.com",
                "GIT_COMMITTER_DATE": "1500000000+0000",
            }
            commit = self.git.commit_tree(tree, m="message", env=env)
            self.assertEqual(commit, "4cfd6b0314682d5a58f80be39850bad1640e9241")

    def test_persistent_cat_file_command(self):
        # Read header only.
        hexsha = "b2339455342180c7cc1e9bba3e9f181f7baa5167"
        g = self.git.cat_file(batch_check=True, istream=subprocess.PIPE, as_process=True)
        g.stdin.write(b"b2339455342180c7cc1e9bba3e9f181f7baa5167\n")
        g.stdin.flush()
        obj_info = g.stdout.readline()

        # Read header + data.
        g = self.git.cat_file(batch=True, istream=subprocess.PIPE, as_process=True)
        g.stdin.write(b"b2339455342180c7cc1e9bba3e9f181f7baa5167\n")
        g.stdin.flush()
        obj_info_two = g.stdout.readline()
        self.assertEqual(obj_info, obj_info_two)

        # Read data - have to read it in one large chunk.
        size = int(obj_info.split()[2])
        g.stdout.read(size)
        g.stdout.read(1)

        # Now we should be able to read a new object.
        g.stdin.write(b"b2339455342180c7cc1e9bba3e9f181f7baa5167\n")
        g.stdin.flush()
        self.assertEqual(g.stdout.readline(), obj_info)

        # Same can be achieved using the respective command functions.
        hexsha, typename, size = self.git.get_object_header(hexsha)
        hexsha, typename_two, size_two, _ = self.git.get_object_data(hexsha)
        self.assertEqual(typename, typename_two)
        self.assertEqual(size, size_two)

    def test_version(self):
        v = self.git.version_info
        self.assertIsInstance(v, tuple)
        for n in v:
            self.assertIsInstance(n, int)
        # END verify number types

    def test_cmd_override(self):
        with mock.patch.object(
            type(self.git),
            "GIT_PYTHON_GIT_EXECUTABLE",
            osp.join("some", "path", "which", "doesn't", "exist", "gitbinary"),
        ):
            self.assertRaises(GitCommandNotFound, self.git.version)

    def test_refresh(self):
        # Test a bad git path refresh.
        self.assertRaises(GitCommandNotFound, refresh, "yada")

        # Test a good path refresh.
        which_cmd = "where" if os.name == "nt" else "command -v"
        path = os.popen("{0} git".format(which_cmd)).read().strip().split("\n")[0]
        refresh(path)

    def test_options_are_passed_to_git(self):
        # This works because any command after git --version is ignored.
        git_version = self.git(version=True).NoOp()
        git_command_version = self.git.version()
        self.assertEqual(git_version, git_command_version)

    def test_persistent_options(self):
        git_command_version = self.git.version()
        # Analog to test_options_are_passed_to_git.
        self.git.set_persistent_git_options(version=True)
        git_version = self.git.NoOp()
        self.assertEqual(git_version, git_command_version)
        # Subsequent calls keep this option:
        git_version_2 = self.git.NoOp()
        self.assertEqual(git_version_2, git_command_version)

        # Reset to empty:
        self.git.set_persistent_git_options()
        self.assertRaises(GitCommandError, self.git.NoOp)

    def test_single_char_git_options_are_passed_to_git(self):
        input_value = "TestValue"
        output_value = self.git(c="user.name=%s" % input_value).config("--get", "user.name")
        self.assertEqual(input_value, output_value)

    def test_change_to_transform_kwargs_does_not_break_command_options(self):
        self.git.log(n=1)

    def test_insert_after_kwarg_raises(self):
        # This isn't a complete add command, which doesn't matter here.
        self.assertRaises(ValueError, self.git.remote, "add", insert_kwargs_after="foo")

    def test_env_vars_passed_to_git(self):
        editor = "non_existent_editor"
        with mock.patch.dict(os.environ, {"GIT_EDITOR": editor}):
            self.assertEqual(self.git.var("GIT_EDITOR"), editor)

    @with_rw_directory
    def test_environment(self, rw_dir):
        # Sanity check.
        self.assertEqual(self.git.environment(), {})

        # Make sure the context manager works and cleans up after itself.
        with self.git.custom_environment(PWD="/tmp"):
            self.assertEqual(self.git.environment(), {"PWD": "/tmp"})

        self.assertEqual(self.git.environment(), {})

        old_env = self.git.update_environment(VARKEY="VARVALUE")
        # The returned dict can be used to revert the change, hence why it has
        # an entry with value 'None'.
        self.assertEqual(old_env, {"VARKEY": None})
        self.assertEqual(self.git.environment(), {"VARKEY": "VARVALUE"})

        new_env = self.git.update_environment(**old_env)
        self.assertEqual(new_env, {"VARKEY": "VARVALUE"})
        self.assertEqual(self.git.environment(), {})

        path = osp.join(rw_dir, "failing-script.sh")
        with open(path, "wt") as stream:
            stream.write("#!/usr/bin/env sh\n" "echo FOO\n")
        os.chmod(path, 0o777)

        rw_repo = Repo.init(osp.join(rw_dir, "repo"))
        remote = rw_repo.create_remote("ssh-origin", "ssh://git@server/foo")

        with rw_repo.git.custom_environment(GIT_SSH=path):
            try:
                remote.fetch()
            except GitCommandError as err:
                self.assertIn("FOO", str(err))

    def test_handle_process_output(self):
        from git.cmd import handle_process_output

        line_count = 5002
        count = [None, 0, 0]

        def counter_stdout(line):
            count[1] += 1

        def counter_stderr(line):
            count[2] += 1

        cmdline = [
            sys.executable,
            fixture_path("cat_file.py"),
            str(fixture_path("issue-301_stderr")),
        ]
        proc = subprocess.Popen(
            cmdline,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            creationflags=cmd.PROC_CREATIONFLAGS,
        )

        handle_process_output(proc, counter_stdout, counter_stderr, finalize_process)

        self.assertEqual(count[1], line_count)
        self.assertEqual(count[2], line_count)

    def test_execute_kwargs_set_agrees_with_method(self):
        parameter_names = inspect.signature(cmd.Git.execute).parameters.keys()
        self_param, command_param, *most_params, extra_kwargs_param = parameter_names
        self.assertEqual(self_param, "self")
        self.assertEqual(command_param, "command")
        self.assertEqual(set(most_params), cmd.execute_kwargs)  # Most important.
        self.assertEqual(extra_kwargs_param, "subprocess_kwargs")
