# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import contextlib
import gc
import inspect
import logging
import os
import os.path as osp
from pathlib import Path
import pickle
import re
import shutil
import subprocess
import sys
import tempfile
from unittest import skipUnless

if sys.version_info >= (3, 8):
    from unittest import mock
else:
    import mock  # To be able to examine call_args.kwargs on a mock.

import ddt

from git import Git, GitCommandError, GitCommandNotFound, Repo, cmd, refresh
from git.util import cwd, finalize_process

from test.lib import TestBase, fixture_path, with_rw_directory


@contextlib.contextmanager
def _patch_out_env(name):
    try:
        old_value = os.environ[name]
    except KeyError:
        old_value = None
    else:
        del os.environ[name]
    try:
        yield
    finally:
        if old_value is not None:
            os.environ[name] = old_value


@contextlib.contextmanager
def _rollback_refresh():
    old_git_executable = Git.GIT_PYTHON_GIT_EXECUTABLE

    if old_git_executable is None:
        raise RuntimeError("no executable string (need initial refresh before test)")

    try:
        yield old_git_executable  # Provide the old value for convenience.
    finally:
        # The cleanup refresh should always raise an exception if it fails, since if it
        # fails then previously discovered test results could be misleading and, more
        # importantly, subsequent tests may be unable to run or give misleading results.
        # So pre-set a non-None value, so that the cleanup will be a "second" refresh.
        # This covers cases where a test has set it to None to test a "first" refresh.
        Git.GIT_PYTHON_GIT_EXECUTABLE = Git.git_exec_name

        # Do the cleanup refresh. This sets Git.GIT_PYTHON_GIT_EXECUTABLE to old_value
        # in most cases. The reason to call it is to achieve other associated state
        # changes as well, which include updating attributes of the FetchInfo class.
        refresh()


@contextlib.contextmanager
def _fake_git(*version_info):
    fake_version = ".".join(map(str, version_info))
    fake_output = f"git version {fake_version} (fake)"

    with tempfile.TemporaryDirectory() as tdir:
        if sys.platform == "win32":
            fake_git = Path(tdir, "fake-git.cmd")
            script = f"@echo {fake_output}\n"
            fake_git.write_text(script, encoding="utf-8")
        else:
            fake_git = Path(tdir, "fake-git")
            script = f"#!/bin/sh\necho '{fake_output}'\n"
            fake_git.write_text(script, encoding="utf-8")
            fake_git.chmod(0o755)

        yield str(fake_git.absolute())


def _rename_with_stem(path, new_stem):
    if sys.version_info >= (3, 9):
        path.rename(path.with_stem(new_stem))
    else:
        path.rename(path.with_name(new_stem + path.suffix))


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
            with mock.patch.object(cmd, "safer_popen", wraps=cmd.safer_popen) as mock_safer_popen:
                # Use a command with no arguments (besides the program name), so it runs
                # with or without a shell, on all OSes, with the same effect.
                self.git.execute(["git"], with_exceptions=False, shell=value_in_call)

        return mock_safer_popen

    @ddt.idata(_shell_cases)
    def test_it_uses_shell_or_not_as_specified(self, case):
        """A bool passed as ``shell=`` takes precedence over `Git.USE_SHELL`."""
        value_in_call, value_from_class, expected_popen_arg = case
        mock_safer_popen = self._do_shell_combo(value_in_call, value_from_class)
        mock_safer_popen.assert_called_once()
        self.assertIs(mock_safer_popen.call_args.kwargs["shell"], expected_popen_arg)

    @ddt.idata(full_case[:2] for full_case in _shell_cases)
    def test_it_logs_if_it_uses_a_shell(self, case):
        """``shell=`` in the log message agrees with what is passed to `Popen`."""
        value_in_call, value_from_class = case
        with self.assertLogs(cmd.__name__, level=logging.DEBUG) as log_watcher:
            mock_safer_popen = self._do_shell_combo(value_in_call, value_from_class)
        self._assert_logged_for_popen(log_watcher, "shell", mock_safer_popen.call_args.kwargs["shell"])

    @ddt.data(
        ("None", None),
        ("<valid stream>", subprocess.PIPE),
    )
    def test_it_logs_istream_summary_for_stdin(self, case):
        expected_summary, istream_argument = case
        with self.assertLogs(cmd.__name__, level=logging.DEBUG) as log_watcher:
            self.git.execute(["git", "version"], istream=istream_argument)
        self._assert_logged_for_popen(log_watcher, "stdin", expected_summary)

    def test_it_executes_git_and_returns_result(self):
        self.assertRegex(self.git.execute(["git", "version"]), r"^git version [\d\.]{2}.*$")

    @ddt.data(
        # chdir_to_repo, shell, command, use_shell_impostor
        (False, False, ["git", "version"], False),
        (False, True, "git version", False),
        (False, True, "git version", True),
        (True, False, ["git", "version"], False),
        (True, True, "git version", False),
        (True, True, "git version", True),
    )
    @with_rw_directory
    def test_it_executes_git_not_from_cwd(self, rw_dir, case):
        chdir_to_repo, shell, command, use_shell_impostor = case

        repo = Repo.init(rw_dir)

        if sys.platform == "win32":
            # Copy an actual binary executable that is not git. (On Windows, running
            # "hostname" only displays the hostname, it never tries to change it.)
            other_exe_path = Path(os.environ["SystemRoot"], "system32", "hostname.exe")
            impostor_path = Path(rw_dir, "git.exe")
            shutil.copy(other_exe_path, impostor_path)
        else:
            # Create a shell script that doesn't do anything.
            impostor_path = Path(rw_dir, "git")
            impostor_path.write_text("#!/bin/sh\n", encoding="utf-8")
            os.chmod(impostor_path, 0o755)

        if use_shell_impostor:
            shell_name = "cmd.exe" if sys.platform == "win32" else "sh"
            shutil.copy(impostor_path, Path(rw_dir, shell_name))

        with contextlib.ExitStack() as stack:
            if chdir_to_repo:
                stack.enter_context(cwd(rw_dir))
            if use_shell_impostor:
                stack.enter_context(_patch_out_env("ComSpec"))

            # Run the command without raising an exception on failure, as the exception
            # message is currently misleading when the command is a string rather than a
            # sequence of strings (it really runs "git", but then wrongly reports "g").
            output = repo.git.execute(command, with_exceptions=False, shell=shell)

        self.assertRegex(output, r"^git version\b")

    @skipUnless(
        sys.platform == "win32",
        "The regression only affected Windows, and this test logic is OS-specific.",
    )
    def test_it_avoids_upcasing_unrelated_environment_variable_names(self):
        old_name = "28f425ca_d5d8_4257_b013_8d63166c8158"
        if old_name == old_name.upper():
            raise RuntimeError("test bug or strange locale: old_name invariant under upcasing")

        # Step 1
        #
        # Set the environment variable in this parent process. Because os.putenv is a
        # thin wrapper around a system API, os.environ never sees the variable in this
        # parent process, so the name is not upcased even on Windows.
        os.putenv(old_name, "1")

        # Step 2
        #
        # Create the child process that inherits the environment variable. The child
        # uses GitPython, and we are testing that it passes the variable with the exact
        # original name to its own child process (the grandchild).
        cmdline = [
            sys.executable,
            fixture_path("env_case.py"),  # Contains steps 3 and 4.
            self.rorepo.working_dir,
            old_name,
        ]

        # Run steps 3 and 4.
        pair_text = subprocess.check_output(cmdline, shell=False, text=True)

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
        with tempfile.TemporaryFile() as tmp_file:
            with self.assertRaises(GitCommandError):
                self.git.checkout("non-existent-branch", output_stream=tmp_file)

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

    def test_version_info(self):
        """The version_info attribute is a tuple of up to four ints."""
        v = self.git.version_info
        self.assertIsInstance(v, tuple)
        self.assertLessEqual(len(v), 4)
        for n in v:
            self.assertIsInstance(n, int)

    def test_version_info_pickleable(self):
        """The version_info attribute is usable on unpickled Git instances."""
        deserialized = pickle.loads(pickle.dumps(self.git))
        v = deserialized.version_info
        self.assertIsInstance(v, tuple)
        self.assertLessEqual(len(v), 4)
        for n in v:
            self.assertIsInstance(n, int)

    @ddt.data(
        (("123", "456", "789"), (123, 456, 789)),
        (("12", "34", "56", "78"), (12, 34, 56, 78)),
        (("12", "34", "56", "78", "90"), (12, 34, 56, 78)),
        (("1", "2", "a", "3"), (1, 2)),
        (("1", "-2", "3"), (1,)),
        (("1", "2a", "3"), (1,)),  # Subject to change.
    )
    def test_version_info_is_leading_numbers(self, case):
        fake_fields, expected_version_info = case
        with _rollback_refresh():
            with _fake_git(*fake_fields) as path:
                refresh(path)
                new_git = Git()
                self.assertEqual(new_git.version_info, expected_version_info)

    def test_git_exc_name_is_git(self):
        self.assertEqual(self.git.git_exec_name, "git")

    def test_cmd_override(self):
        """Directly set bad GIT_PYTHON_GIT_EXECUTABLE causes git operations to raise."""
        bad_path = osp.join("some", "path", "which", "doesn't", "exist", "gitbinary")
        with mock.patch.object(Git, "GIT_PYTHON_GIT_EXECUTABLE", bad_path):
            with self.assertRaises(GitCommandNotFound) as ctx:
                self.git.version()
            self.assertEqual(ctx.exception.command, [bad_path, "version"])

    @ddt.data(("0",), ("q",), ("quiet",), ("s",), ("silence",), ("silent",), ("n",), ("none",))
    def test_initial_refresh_from_bad_git_path_env_quiet(self, case):
        """In "q" mode, bad initial path sets "git" and is quiet."""
        (mode,) = case
        set_vars = {
            "GIT_PYTHON_GIT_EXECUTABLE": str(Path("yada").absolute()),  # Any bad path.
            "GIT_PYTHON_REFRESH": mode,
        }
        with _rollback_refresh():
            Git.GIT_PYTHON_GIT_EXECUTABLE = None  # Simulate startup.

            with mock.patch.dict(os.environ, set_vars):
                refresh()
                self.assertEqual(self.git.GIT_PYTHON_GIT_EXECUTABLE, "git")

    @ddt.data(("1",), ("w",), ("warn",), ("warning",), ("l",), ("log",))
    def test_initial_refresh_from_bad_git_path_env_warn(self, case):
        """In "w" mode, bad initial path sets "git" and warns, by logging."""
        (mode,) = case
        env_vars = {
            "GIT_PYTHON_GIT_EXECUTABLE": str(Path("yada").absolute()),  # Any bad path.
            "GIT_PYTHON_REFRESH": mode,
        }
        with _rollback_refresh():
            Git.GIT_PYTHON_GIT_EXECUTABLE = None  # Simulate startup.

            with mock.patch.dict(os.environ, env_vars):
                with self.assertLogs(cmd.__name__, logging.CRITICAL) as ctx:
                    refresh()
                self.assertEqual(len(ctx.records), 1)
                message = ctx.records[0].getMessage()
                self.assertRegex(message, r"\ABad git executable.\n")
                self.assertEqual(self.git.GIT_PYTHON_GIT_EXECUTABLE, "git")

    @ddt.data(("2",), ("r",), ("raise",), ("e",), ("error",))
    def test_initial_refresh_from_bad_git_path_env_error(self, case):
        """In "e" mode, bad initial path raises an exception."""
        (mode,) = case
        env_vars = {
            "GIT_PYTHON_GIT_EXECUTABLE": str(Path("yada").absolute()),  # Any bad path.
            "GIT_PYTHON_REFRESH": mode,
        }
        with _rollback_refresh():
            Git.GIT_PYTHON_GIT_EXECUTABLE = None  # Simulate startup.

            with mock.patch.dict(os.environ, env_vars):
                with self.assertRaisesRegex(ImportError, r"\ABad git executable.\n"):
                    refresh()

    def test_initial_refresh_from_good_absolute_git_path_env(self):
        """Good initial absolute path from environment is set."""
        absolute_path = shutil.which("git")

        with _rollback_refresh():
            Git.GIT_PYTHON_GIT_EXECUTABLE = None  # Simulate startup.

            with mock.patch.dict(os.environ, {"GIT_PYTHON_GIT_EXECUTABLE": absolute_path}):
                refresh()
                self.assertEqual(self.git.GIT_PYTHON_GIT_EXECUTABLE, absolute_path)

    def test_initial_refresh_from_good_relative_git_path_env(self):
        """Good initial relative path from environment is kept relative and set."""
        with _rollback_refresh():
            # Set the fallback to a string that wouldn't work and isn't "git", so we are
            # more likely to detect if "git" is not set from the environment variable.
            with mock.patch.object(Git, "git_exec_name", ""):
                Git.GIT_PYTHON_GIT_EXECUTABLE = None  # Simulate startup.

                # Now observe if setting the environment variable to "git" takes effect.
                with mock.patch.dict(os.environ, {"GIT_PYTHON_GIT_EXECUTABLE": "git"}):
                    refresh()
                    self.assertEqual(self.git.GIT_PYTHON_GIT_EXECUTABLE, "git")

    def test_refresh_from_bad_absolute_git_path_env(self):
        """Bad absolute path from environment is reported and not set."""
        absolute_path = str(Path("yada").absolute())
        expected_pattern = rf"\n[ \t]*cmdline: {re.escape(absolute_path)}\Z"

        with _rollback_refresh() as old_git_executable:
            with mock.patch.dict(os.environ, {"GIT_PYTHON_GIT_EXECUTABLE": absolute_path}):
                with self.assertRaisesRegex(GitCommandNotFound, expected_pattern):
                    refresh()
                self.assertEqual(self.git.GIT_PYTHON_GIT_EXECUTABLE, old_git_executable)

    def test_refresh_from_bad_relative_git_path_env(self):
        """Bad relative path from environment is kept relative and reported, not set."""
        # Relative paths are not resolved when refresh() is called with no arguments, so
        # use a string that's very unlikely to be a command name found in a path lookup.
        relative_path = "yada-e47e70c6-acbf-40f8-ad65-13af93c2195b"
        expected_pattern = rf"\n[ \t]*cmdline: {re.escape(relative_path)}\Z"

        with _rollback_refresh() as old_git_executable:
            with mock.patch.dict(os.environ, {"GIT_PYTHON_GIT_EXECUTABLE": relative_path}):
                with self.assertRaisesRegex(GitCommandNotFound, expected_pattern):
                    refresh()
                self.assertEqual(self.git.GIT_PYTHON_GIT_EXECUTABLE, old_git_executable)

    def test_refresh_from_good_absolute_git_path_env(self):
        """Good absolute path from environment is set."""
        absolute_path = shutil.which("git")

        with _rollback_refresh():
            with mock.patch.dict(os.environ, {"GIT_PYTHON_GIT_EXECUTABLE": absolute_path}):
                refresh()
                self.assertEqual(self.git.GIT_PYTHON_GIT_EXECUTABLE, absolute_path)

    def test_refresh_from_good_relative_git_path_env(self):
        """Good relative path from environment is kept relative and set."""
        with _rollback_refresh():
            # Set as the executable name a string that wouldn't work and isn't "git".
            Git.GIT_PYTHON_GIT_EXECUTABLE = ""

            # Now observe if setting the environment variable to "git" takes effect.
            with mock.patch.dict(os.environ, {"GIT_PYTHON_GIT_EXECUTABLE": "git"}):
                refresh()
                self.assertEqual(self.git.GIT_PYTHON_GIT_EXECUTABLE, "git")

    def test_refresh_with_bad_absolute_git_path_arg(self):
        """Bad absolute path arg is reported and not set."""
        absolute_path = str(Path("yada").absolute())
        expected_pattern = rf"\n[ \t]*cmdline: {re.escape(absolute_path)}\Z"

        with _rollback_refresh() as old_git_executable:
            with self.assertRaisesRegex(GitCommandNotFound, expected_pattern):
                refresh(absolute_path)
            self.assertEqual(self.git.GIT_PYTHON_GIT_EXECUTABLE, old_git_executable)

    def test_refresh_with_bad_relative_git_path_arg(self):
        """Bad relative path arg is resolved to absolute path and reported, not set."""
        absolute_path = str(Path("yada").absolute())
        expected_pattern = rf"\n[ \t]*cmdline: {re.escape(absolute_path)}\Z"

        with _rollback_refresh() as old_git_executable:
            with self.assertRaisesRegex(GitCommandNotFound, expected_pattern):
                refresh("yada")
            self.assertEqual(self.git.GIT_PYTHON_GIT_EXECUTABLE, old_git_executable)

    def test_refresh_with_good_absolute_git_path_arg(self):
        """Good absolute path arg is set."""
        absolute_path = shutil.which("git")

        with _rollback_refresh():
            refresh(absolute_path)
            self.assertEqual(self.git.GIT_PYTHON_GIT_EXECUTABLE, absolute_path)

    def test_refresh_with_good_relative_git_path_arg(self):
        """Good relative path arg is resolved to absolute path and set."""
        absolute_path = shutil.which("git")
        dirname, basename = osp.split(absolute_path)

        with cwd(dirname):
            with _rollback_refresh():
                refresh(basename)
                self.assertEqual(self.git.GIT_PYTHON_GIT_EXECUTABLE, absolute_path)

    def test_version_info_is_cached(self):
        fake_version_info = (123, 456, 789)
        with _rollback_refresh():
            with _fake_git(*fake_version_info) as path:
                new_git = Git()  # Not cached yet.
                refresh(path)
                self.assertEqual(new_git.version_info, fake_version_info)
                os.remove(path)  # Arrange that a second subprocess call would fail.
                self.assertEqual(new_git.version_info, fake_version_info)

    def test_version_info_cache_is_per_instance(self):
        with _rollback_refresh():
            with _fake_git(123, 456, 789) as path:
                git1 = Git()
                git2 = Git()
                refresh(path)
                git1.version_info
                os.remove(path)  # Arrange that the second subprocess call will fail.
                with self.assertRaises(GitCommandNotFound):
                    git2.version_info
                git1.version_info

    def test_version_info_cache_is_not_pickled(self):
        with _rollback_refresh():
            with _fake_git(123, 456, 789) as path:
                git1 = Git()
                refresh(path)
                git1.version_info
                git2 = pickle.loads(pickle.dumps(git1))
                os.remove(path)  # Arrange that the second subprocess call will fail.
                with self.assertRaises(GitCommandNotFound):
                    git2.version_info
                git1.version_info

    def test_successful_refresh_with_arg_invalidates_cached_version_info(self):
        with _rollback_refresh():
            with _fake_git(11, 111, 1) as path1:
                with _fake_git(22, 222, 2) as path2:
                    new_git = Git()
                    refresh(path1)
                    new_git.version_info
                    refresh(path2)
                    self.assertEqual(new_git.version_info, (22, 222, 2))

    def test_failed_refresh_with_arg_does_not_invalidate_cached_version_info(self):
        with _rollback_refresh():
            with _fake_git(11, 111, 1) as path1:
                with _fake_git(22, 222, 2) as path2:
                    new_git = Git()
                    refresh(path1)
                    new_git.version_info
                    os.remove(path1)  # Arrange that a repeat call for path1 would fail.
                    os.remove(path2)  # Arrange that the new call for path2 will fail.
                    with self.assertRaises(GitCommandNotFound):
                        refresh(path2)
                    self.assertEqual(new_git.version_info, (11, 111, 1))

    def test_successful_refresh_with_same_arg_invalidates_cached_version_info(self):
        """Changing git at the same path and refreshing affects version_info."""
        with _rollback_refresh():
            with _fake_git(11, 111, 1) as path1:
                with _fake_git(22, 222, 2) as path2:
                    new_git = Git()
                    refresh(path1)
                    new_git.version_info
                    shutil.copy(path2, path1)
                    refresh(path1)  # The fake git at path1 has a different version now.
                    self.assertEqual(new_git.version_info, (22, 222, 2))

    def test_successful_refresh_with_env_invalidates_cached_version_info(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(_rollback_refresh())
            path1 = stack.enter_context(_fake_git(11, 111, 1))
            path2 = stack.enter_context(_fake_git(22, 222, 2))
            with mock.patch.dict(os.environ, {"GIT_PYTHON_GIT_EXECUTABLE": path1}):
                new_git = Git()
                refresh()
                new_git.version_info
            with mock.patch.dict(os.environ, {"GIT_PYTHON_GIT_EXECUTABLE": path2}):
                refresh()
                self.assertEqual(new_git.version_info, (22, 222, 2))

    def test_failed_refresh_with_env_does_not_invalidate_cached_version_info(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(_rollback_refresh())
            path1 = stack.enter_context(_fake_git(11, 111, 1))
            path2 = stack.enter_context(_fake_git(22, 222, 2))
            with mock.patch.dict(os.environ, {"GIT_PYTHON_GIT_EXECUTABLE": path1}):
                new_git = Git()
                refresh()
                new_git.version_info
            os.remove(path1)  # Arrange that a repeat call for path1 would fail.
            os.remove(path2)  # Arrange that the new call for path2 will fail.
            with mock.patch.dict(os.environ, {"GIT_PYTHON_GIT_EXECUTABLE": path2}):
                with self.assertRaises(GitCommandNotFound):
                    refresh(path2)
                self.assertEqual(new_git.version_info, (11, 111, 1))

    def test_successful_refresh_with_same_env_invalidates_cached_version_info(self):
        """Changing git at the same path/command and refreshing affects version_info."""
        with contextlib.ExitStack() as stack:
            stack.enter_context(_rollback_refresh())
            path1 = stack.enter_context(_fake_git(11, 111, 1))
            path2 = stack.enter_context(_fake_git(22, 222, 2))
            with mock.patch.dict(os.environ, {"GIT_PYTHON_GIT_EXECUTABLE": path1}):
                new_git = Git()
                refresh()
                new_git.version_info
                shutil.copy(path2, path1)
                refresh()  # The fake git at path1 has a different version now.
                self.assertEqual(new_git.version_info, (22, 222, 2))

    def test_successful_default_refresh_invalidates_cached_version_info(self):
        """Refreshing updates version after a filesystem change adds a git command."""
        # The key assertion here is the last. The others mainly verify the test itself.
        with contextlib.ExitStack() as stack:
            stack.enter_context(_rollback_refresh())

            path1 = Path(stack.enter_context(_fake_git(11, 111, 1)))
            path2 = Path(stack.enter_context(_fake_git(22, 222, 2)))

            new_path_var = f"{path1.parent}{os.pathsep}{path2.parent}"
            stack.enter_context(mock.patch.dict(os.environ, {"PATH": new_path_var}))
            stack.enter_context(_patch_out_env("GIT_PYTHON_GIT_EXECUTABLE"))

            if sys.platform == "win32":
                # On Windows, use a shell so "git" finds "git.cmd". The correct and safe
                # ways to do this straightforwardly are to set GIT_PYTHON_GIT_EXECUTABLE
                # to git.cmd in the environment, or call git.refresh with the command's
                # full path. See the Git.USE_SHELL docstring for deprecation details.
                # But this tests a "default" scenario where neither is done. The
                # approach used here, setting USE_SHELL to True so PATHEXT is honored,
                # should not be used in production code (nor even in most test cases).
                stack.enter_context(mock.patch.object(Git, "USE_SHELL", True))

            new_git = Git()
            _rename_with_stem(path2, "git")  # "Install" git, "late" in the PATH.
            refresh()
            self.assertEqual(new_git.version_info, (22, 222, 2), 'before "downgrade"')
            _rename_with_stem(path1, "git")  # "Install" another, higher priority.
            self.assertEqual(new_git.version_info, (22, 222, 2), "stale version")
            refresh()
            self.assertEqual(new_git.version_info, (11, 111, 1), "fresh version")

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
        from git.cmd import handle_process_output, safer_popen

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
        proc = safer_popen(
            cmdline,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
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
