# test_util.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: https://opensource.org/license/bsd-3-clause/

import ast
import contextlib
from datetime import datetime
import os
import pathlib
import pickle
import stat
import subprocess
import sys
import tempfile
import time
from unittest import SkipTest, mock, skipIf, skipUnless

import ddt
import pytest

from git.cmd import dashify
from git.compat import is_win
from git.objects.util import (
    altz_to_utctz_str,
    from_timestamp,
    parse_date,
    tzoffset,
    utctz_to_altz,
    verify_utctz,
)
from git.util import (
    Actor,
    BlockingLockFile,
    IterableList,
    LockFile,
    cygpath,
    decygpath,
    get_user_id,
    remove_password_if_present,
    rmtree,
)
from test.lib import TestBase, with_rw_repo


class _Member:
    """A member of an IterableList."""

    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f"{type(self).__name__}({self.name!r})"


@contextlib.contextmanager
def _tmpdir_to_force_permission_error():
    """Context manager to test permission errors in situations where they are not overcome."""
    if sys.platform == "cygwin":
        raise SkipTest("Cygwin can't set the permissions that make the test meaningful.")
    if sys.version_info < (3, 8):
        raise SkipTest("In 3.7, TemporaryDirectory doesn't clean up after weird permissions.")

    with tempfile.TemporaryDirectory() as parent:
        td = pathlib.Path(parent, "testdir")
        td.mkdir()
        (td / "x").write_bytes(b"")
        (td / "x").chmod(stat.S_IRUSR)  # Set up PermissionError on Windows.
        td.chmod(stat.S_IRUSR | stat.S_IXUSR)  # Set up PermissionError on Unix.
        yield td


@contextlib.contextmanager
def _tmpdir_for_file_not_found():
    """Context manager to test errors deleting a directory that are not due to permissions."""
    with tempfile.TemporaryDirectory() as parent:
        yield pathlib.Path(parent, "testdir")  # It is deliberately never created.


@ddt.ddt
class TestUtils(TestBase):
    def test_rmtree_deletes_nested_dir_with_files(self):
        with tempfile.TemporaryDirectory() as parent:
            td = pathlib.Path(parent, "testdir")
            for d in td, td / "q", td / "s":
                d.mkdir()
            for f in (
                td / "p",
                td / "q" / "w",
                td / "q" / "x",
                td / "r",
                td / "s" / "y",
                td / "s" / "z",
            ):
                f.write_bytes(b"")

            try:
                rmtree(td)
            except SkipTest as ex:
                self.fail(f"rmtree unexpectedly attempts skip: {ex!r}")

            self.assertFalse(td.exists())

    @skipIf(
        sys.platform == "cygwin",
        "Cygwin can't set the permissions that make the test meaningful.",
    )
    def test_rmtree_deletes_dir_with_readonly_files(self):
        # Automatically works on Unix, but requires special handling on Windows.
        # Not to be confused with what _tmpdir_to_force_permission_error sets up (see below).
        with tempfile.TemporaryDirectory() as parent:
            td = pathlib.Path(parent, "testdir")
            for d in td, td / "sub":
                d.mkdir()
            for f in td / "x", td / "sub" / "y":
                f.write_bytes(b"")
                f.chmod(0)

            try:
                rmtree(td)
            except SkipTest as ex:
                self.fail(f"rmtree unexpectedly attempts skip: {ex!r}")

            self.assertFalse(td.exists())

    def test_rmtree_can_wrap_exceptions(self):
        """rmtree wraps PermissionError when HIDE_WINDOWS_KNOWN_ERRORS is true."""
        with _tmpdir_to_force_permission_error() as td:
            # Access the module through sys.modules so it is unambiguous which module's
            # attribute we patch: the original git.util, not git.index.util even though
            # git.index.util "replaces" git.util and is what "import git.util" gives us.
            with mock.patch.object(sys.modules["git.util"], "HIDE_WINDOWS_KNOWN_ERRORS", True):
                # Disable common chmod functions so the callback can't fix the problem.
                with mock.patch.object(os, "chmod"), mock.patch.object(pathlib.Path, "chmod"):
                    # Now we can see how an intractable PermissionError is treated.
                    with self.assertRaises(SkipTest):
                        rmtree(td)

    @ddt.data(
        (False, PermissionError, _tmpdir_to_force_permission_error),
        (False, FileNotFoundError, _tmpdir_for_file_not_found),
        (True, FileNotFoundError, _tmpdir_for_file_not_found),
    )
    def test_rmtree_does_not_wrap_unless_called_for(self, case):
        """rmtree doesn't wrap non-PermissionError, nor if HIDE_WINDOWS_KNOWN_ERRORS is false."""
        hide_windows_known_errors, exception_type, tmpdir_context_factory = case

        with tmpdir_context_factory() as td:
            # See comments in test_rmtree_can_wrap_exceptions regarding the patching done here.
            with mock.patch.object(
                sys.modules["git.util"],
                "HIDE_WINDOWS_KNOWN_ERRORS",
                hide_windows_known_errors,
            ):
                with mock.patch.object(os, "chmod"), mock.patch.object(pathlib.Path, "chmod"):
                    with self.assertRaises(exception_type):
                        try:
                            rmtree(td)
                        except SkipTest as ex:
                            self.fail(f"rmtree unexpectedly attempts skip: {ex!r}")

    @ddt.data("HIDE_WINDOWS_KNOWN_ERRORS", "HIDE_WINDOWS_FREEZE_ERRORS")
    def test_env_vars_for_windows_tests(self, name):
        def run_parse(value):
            command = [
                sys.executable,
                "-c",
                f"from git.util import {name}; print(repr({name}))",
            ]
            output = subprocess.check_output(
                command,
                env=None if value is None else dict(os.environ, **{name: value}),
                text=True,
            )
            return ast.literal_eval(output)

        for env_var_value, expected_truth_value in (
            (None, os.name == "nt"),  # True on Windows when the environment variable is unset.
            ("", False),
            (" ", False),
            ("0", False),
            ("1", os.name == "nt"),
            ("false", False),
            ("true", os.name == "nt"),
            ("False", False),
            ("True", os.name == "nt"),
            ("no", False),
            ("yes", os.name == "nt"),
            ("NO", False),
            ("YES", os.name == "nt"),
            (" no  ", False),
            (" yes  ", os.name == "nt"),
        ):
            with self.subTest(env_var_value=env_var_value):
                self.assertIs(run_parse(env_var_value), expected_truth_value)

    _norm_cygpath_pairs = (
        (R"foo\bar", "foo/bar"),
        (R"foo/bar", "foo/bar"),
        (R"C:\Users", "/cygdrive/c/Users"),
        (R"C:\d/e", "/cygdrive/c/d/e"),
        ("C:\\", "/cygdrive/c/"),
        (R"\\server\C$\Users", "//server/C$/Users"),
        (R"\\server\C$", "//server/C$"),
        ("\\\\server\\c$\\", "//server/c$/"),
        (R"\\server\BAR/", "//server/BAR/"),
        (R"D:/Apps", "/cygdrive/d/Apps"),
        (R"D:/Apps\fOO", "/cygdrive/d/Apps/fOO"),
        (R"D:\Apps/123", "/cygdrive/d/Apps/123"),
    )

    _unc_cygpath_pairs = (
        (R"\\?\a:\com", "/cygdrive/a/com"),
        (R"\\?\a:/com", "/cygdrive/a/com"),
        (R"\\?\UNC\server\D$\Apps", "//server/D$/Apps"),
    )

    # FIXME: Mark only the /proc-prefixing cases xfail, somehow (or fix them).
    @pytest.mark.xfail(
        reason="Many return paths prefixed /proc/cygdrive instead.",
        raises=AssertionError,
    )
    @skipUnless(sys.platform == "cygwin", "Paths specifically for Cygwin.")
    @ddt.idata(_norm_cygpath_pairs + _unc_cygpath_pairs)
    def test_cygpath_ok(self, case):
        wpath, cpath = case
        cwpath = cygpath(wpath)
        self.assertEqual(cwpath, cpath, wpath)

    @pytest.mark.xfail(
        reason=R'2nd example r".\bar" -> "bar" fails, returns "./bar"',
        raises=AssertionError,
    )
    @skipUnless(sys.platform == "cygwin", "Paths specifically for Cygwin.")
    @ddt.data(
        (R"./bar", "bar"),
        (R".\bar", "bar"),  # FIXME: Mark only this one xfail, somehow (or fix it).
        (R"../bar", "../bar"),
        (R"..\bar", "../bar"),
        (R"../bar/.\foo/../chu", "../bar/chu"),
    )
    def test_cygpath_norm_ok(self, case):
        wpath, cpath = case
        cwpath = cygpath(wpath)
        self.assertEqual(cwpath, cpath or wpath, wpath)

    @skipUnless(sys.platform == "cygwin", "Paths specifically for Cygwin.")
    @ddt.data(
        R"C:",
        R"C:Relative",
        R"D:Apps\123",
        R"D:Apps/123",
        R"\\?\a:rel",
        R"\\share\a:rel",
    )
    def test_cygpath_invalids(self, wpath):
        cwpath = cygpath(wpath)
        self.assertEqual(cwpath, wpath.replace("\\", "/"), wpath)

    @skipUnless(sys.platform == "cygwin", "Paths specifically for Cygwin.")
    @ddt.idata(_norm_cygpath_pairs)
    def test_decygpath(self, case):
        wpath, cpath = case
        wcpath = decygpath(cpath)
        self.assertEqual(wcpath, wpath.replace("/", "\\"), cpath)

    def test_it_should_dashify(self):
        self.assertEqual("this-is-my-argument", dashify("this_is_my_argument"))
        self.assertEqual("foo", dashify("foo"))

    def test_lock_file(self):
        my_file = tempfile.mktemp()
        lock_file = LockFile(my_file)
        assert not lock_file._has_lock()
        # Release lock we don't have - fine.
        lock_file._release_lock()

        # Get lock.
        lock_file._obtain_lock_or_raise()
        assert lock_file._has_lock()

        # Concurrent access.
        other_lock_file = LockFile(my_file)
        assert not other_lock_file._has_lock()
        self.assertRaises(IOError, other_lock_file._obtain_lock_or_raise)

        lock_file._release_lock()
        assert not lock_file._has_lock()

        other_lock_file._obtain_lock_or_raise()
        self.assertRaises(IOError, lock_file._obtain_lock_or_raise)

        # Auto-release on destruction.
        del other_lock_file
        lock_file._obtain_lock_or_raise()
        lock_file._release_lock()

    def test_blocking_lock_file(self):
        my_file = tempfile.mktemp()
        lock_file = BlockingLockFile(my_file)
        lock_file._obtain_lock()

        # Next one waits for the lock.
        start = time.time()
        wait_time = 0.1
        wait_lock = BlockingLockFile(my_file, 0.05, wait_time)
        self.assertRaises(IOError, wait_lock._obtain_lock)
        elapsed = time.time() - start
        extra_time = 0.02
        if is_win or sys.platform == "cygwin":
            extra_time *= 6  # NOTE: Indeterministic failures without this...
        self.assertLess(elapsed, wait_time + extra_time)

    def test_user_id(self):
        self.assertIn("@", get_user_id())

    def test_parse_date(self):
        # parse_date(from_timestamp()) must return the tuple unchanged.
        for timestamp, offset in (
            (1522827734, -7200),
            (1522827734, 0),
            (1522827734, +3600),
        ):
            self.assertEqual(parse_date(from_timestamp(timestamp, offset)), (timestamp, offset))

        # Test all supported formats.
        def assert_rval(rval, veri_time, offset=0):
            self.assertEqual(len(rval), 2)
            self.assertIsInstance(rval[0], int)
            self.assertIsInstance(rval[1], int)
            self.assertEqual(rval[0], veri_time)
            self.assertEqual(rval[1], offset)

            # Now that we are here, test our conversion functions as well.
            utctz = altz_to_utctz_str(offset)
            self.assertIsInstance(utctz, str)
            self.assertEqual(utctz_to_altz(verify_utctz(utctz)), offset)

        # END assert rval utility

        rfc = ("Thu, 07 Apr 2005 22:13:11 +0000", 0)
        iso = ("2005-04-07T22:13:11 -0200", 7200)
        iso2 = ("2005-04-07 22:13:11 +0400", -14400)
        iso3 = ("2005.04.07 22:13:11 -0000", 0)
        alt = ("04/07/2005 22:13:11", 0)
        alt2 = ("07.04.2005 22:13:11", 0)
        veri_time_utc = 1112911991  # The time this represents, in time since epoch, UTC.
        for date, offset in (rfc, iso, iso2, iso3, alt, alt2):
            assert_rval(parse_date(date), veri_time_utc, offset)
        # END for each date type

        # ...and failure.
        self.assertRaises(ValueError, parse_date, datetime.now())  # Non-aware datetime.
        self.assertRaises(ValueError, parse_date, "invalid format")
        self.assertRaises(ValueError, parse_date, "123456789 -02000")
        self.assertRaises(ValueError, parse_date, " 123456789 -0200")

    def test_actor(self):
        for cr in (None, self.rorepo.config_reader()):
            self.assertIsInstance(Actor.committer(cr), Actor)
            self.assertIsInstance(Actor.author(cr), Actor)
        # END ensure config reader is handled

    @with_rw_repo("HEAD")
    @mock.patch("getpass.getuser")
    def test_actor_get_uid_laziness_not_called(self, rwrepo, mock_get_uid):
        with rwrepo.config_writer() as cw:
            cw.set_value("user", "name", "John Config Doe")
            cw.set_value("user", "email", "jcdoe@example.com")

        cr = rwrepo.config_reader()
        committer = Actor.committer(cr)
        author = Actor.author(cr)

        self.assertEqual(committer.name, "John Config Doe")
        self.assertEqual(committer.email, "jcdoe@example.com")
        self.assertEqual(author.name, "John Config Doe")
        self.assertEqual(author.email, "jcdoe@example.com")
        self.assertFalse(mock_get_uid.called)

        env = {
            "GIT_AUTHOR_NAME": "John Doe",
            "GIT_AUTHOR_EMAIL": "jdoe@example.com",
            "GIT_COMMITTER_NAME": "Jane Doe",
            "GIT_COMMITTER_EMAIL": "jane@example.com",
        }
        os.environ.update(env)
        for cr in (None, rwrepo.config_reader()):
            committer = Actor.committer(cr)
            author = Actor.author(cr)
            self.assertEqual(committer.name, "Jane Doe")
            self.assertEqual(committer.email, "jane@example.com")
            self.assertEqual(author.name, "John Doe")
            self.assertEqual(author.email, "jdoe@example.com")
        self.assertFalse(mock_get_uid.called)

    @mock.patch("getpass.getuser")
    def test_actor_get_uid_laziness_called(self, mock_get_uid):
        mock_get_uid.return_value = "user"
        committer = Actor.committer(None)
        author = Actor.author(None)
        # We can't test with `self.rorepo.config_reader()` here, as the UUID laziness
        # depends on whether the user running the test has their global user.name config set.
        self.assertEqual(committer.name, "user")
        self.assertTrue(committer.email.startswith("user@"))
        self.assertEqual(author.name, "user")
        self.assertTrue(committer.email.startswith("user@"))
        self.assertTrue(mock_get_uid.called)
        self.assertEqual(mock_get_uid.call_count, 2)

    def test_actor_from_string(self):
        self.assertEqual(Actor._from_string("name"), Actor("name", None))
        self.assertEqual(Actor._from_string("name <>"), Actor("name", ""))
        self.assertEqual(
            Actor._from_string("name last another <some-very-long-email@example.com>"),
            Actor("name last another", "some-very-long-email@example.com"),
        )

    @ddt.data(
        ("name", ""),
        ("name", "prefix_"),
    )
    def test_iterable_list(self, case):
        name, prefix = case
        ilist = IterableList(name, prefix)

        name1 = "one"
        name2 = "two"
        m1 = _Member(prefix + name1)
        m2 = _Member(prefix + name2)

        ilist.extend((m1, m2))

        self.assertEqual(len(ilist), 2)

        # Contains works with name and identity.
        self.assertIn(name1, ilist)
        self.assertIn(name2, ilist)
        self.assertIn(m2, ilist)
        self.assertIn(m2, ilist)
        self.assertNotIn("invalid", ilist)

        # With string index.
        self.assertIs(ilist[name1], m1)
        self.assertIs(ilist[name2], m2)

        # With int index.
        self.assertIs(ilist[0], m1)
        self.assertIs(ilist[1], m2)

        # With getattr.
        self.assertIs(ilist.one, m1)
        self.assertIs(ilist.two, m2)

        # Test exceptions.
        self.assertRaises(AttributeError, getattr, ilist, "something")
        self.assertRaises(IndexError, ilist.__getitem__, "something")

        # Delete by name and index.
        self.assertRaises(IndexError, ilist.__delitem__, "something")
        del ilist[name2]
        self.assertEqual(len(ilist), 1)
        self.assertNotIn(name2, ilist)
        self.assertIn(name1, ilist)
        del ilist[0]
        self.assertNotIn(name1, ilist)
        self.assertEqual(len(ilist), 0)

        self.assertRaises(IndexError, ilist.__delitem__, 0)
        self.assertRaises(IndexError, ilist.__delitem__, "something")

    def test_utctz_to_altz(self):
        self.assertEqual(utctz_to_altz("+0000"), 0)
        self.assertEqual(utctz_to_altz("+1400"), -(14 * 3600))
        self.assertEqual(utctz_to_altz("-1200"), 12 * 3600)
        self.assertEqual(utctz_to_altz("+0001"), -60)
        self.assertEqual(utctz_to_altz("+0530"), -(5 * 3600 + 1800))
        self.assertEqual(utctz_to_altz("-0930"), 9 * 3600 + 1800)

    def test_altz_to_utctz_str(self):
        self.assertEqual(altz_to_utctz_str(0), "+0000")
        self.assertEqual(altz_to_utctz_str(-(14 * 3600)), "+1400")
        self.assertEqual(altz_to_utctz_str(12 * 3600), "-1200")
        self.assertEqual(altz_to_utctz_str(-60), "+0001")
        self.assertEqual(altz_to_utctz_str(-(5 * 3600 + 1800)), "+0530")
        self.assertEqual(altz_to_utctz_str(9 * 3600 + 1800), "-0930")

        self.assertEqual(altz_to_utctz_str(1), "+0000")
        self.assertEqual(altz_to_utctz_str(59), "+0000")
        self.assertEqual(altz_to_utctz_str(-1), "+0000")
        self.assertEqual(altz_to_utctz_str(-59), "+0000")

    def test_from_timestamp(self):
        # Correct offset: UTC+2, should return datetime + tzoffset(+2).
        altz = utctz_to_altz("+0200")
        self.assertEqual(
            datetime.fromtimestamp(1522827734, tzoffset(altz)),
            from_timestamp(1522827734, altz),
        )

        # Wrong offset: UTC+58, should return datetime + tzoffset(UTC).
        altz = utctz_to_altz("+5800")
        self.assertEqual(
            datetime.fromtimestamp(1522827734, tzoffset(0)),
            from_timestamp(1522827734, altz),
        )

        # Wrong offset: UTC-9000, should return datetime + tzoffset(UTC).
        altz = utctz_to_altz("-9000")
        self.assertEqual(
            datetime.fromtimestamp(1522827734, tzoffset(0)),
            from_timestamp(1522827734, altz),
        )

    def test_pickle_tzoffset(self):
        t1 = tzoffset(555)
        t2 = pickle.loads(pickle.dumps(t1))
        self.assertEqual(t1._offset, t2._offset)
        self.assertEqual(t1._name, t2._name)

    def test_remove_password_from_command_line(self):
        username = "fakeuser"
        password = "fakepassword1234"
        url_with_user_and_pass = "https://{}:{}@fakerepo.example.com/testrepo".format(username, password)
        url_with_user = "https://{}@fakerepo.example.com/testrepo".format(username)
        url_with_pass = "https://:{}@fakerepo.example.com/testrepo".format(password)
        url_without_user_or_pass = "https://fakerepo.example.com/testrepo"

        cmd_1 = ["git", "clone", "-v", url_with_user_and_pass]
        cmd_2 = ["git", "clone", "-v", url_with_user]
        cmd_3 = ["git", "clone", "-v", url_with_pass]
        cmd_4 = ["git", "clone", "-v", url_without_user_or_pass]
        cmd_5 = ["no", "url", "in", "this", "one"]

        redacted_cmd_1 = remove_password_if_present(cmd_1)
        assert username not in " ".join(redacted_cmd_1)
        assert password not in " ".join(redacted_cmd_1)
        # Check that we use a copy.
        assert cmd_1 is not redacted_cmd_1
        assert username in " ".join(cmd_1)
        assert password in " ".join(cmd_1)

        redacted_cmd_2 = remove_password_if_present(cmd_2)
        assert username not in " ".join(redacted_cmd_2)
        assert password not in " ".join(redacted_cmd_2)

        redacted_cmd_3 = remove_password_if_present(cmd_3)
        assert username not in " ".join(redacted_cmd_3)
        assert password not in " ".join(redacted_cmd_3)

        assert cmd_4 == remove_password_if_present(cmd_4)
        assert cmd_5 == remove_password_if_present(cmd_5)
