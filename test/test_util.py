# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import ast
from datetime import datetime
import os
import pathlib
import pickle
import stat
import subprocess
import sys
import tempfile
import time
from unittest import SkipTest, mock

import ddt
import pytest

from git.cmd import dashify
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


@pytest.fixture
def permission_error_tmpdir(tmp_path):
    """Fixture to test permissions errors in situations where they are not overcome."""
    td = tmp_path / "testdir"
    td.mkdir()
    (td / "x").touch()

    # Set up PermissionError on Windows, where we can't delete read-only files.
    (td / "x").chmod(stat.S_IRUSR)

    # Set up PermissionError on Unix, where non-root users can't delete files in
    # read-only directories. (Tests that rely on this and assert that rmtree raises
    # PermissionError will fail if they are run as root.)
    td.chmod(stat.S_IRUSR | stat.S_IXUSR)

    yield td


class TestRmtree:
    """Tests for :func:`git.util.rmtree`."""

    def test_deletes_nested_dir_with_files(self, tmp_path):
        td = tmp_path / "testdir"

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
            f.touch()

        try:
            rmtree(td)
        except SkipTest as ex:
            pytest.fail(f"rmtree unexpectedly attempts skip: {ex!r}")

        assert not td.exists()

    @pytest.mark.skipif(
        sys.platform == "cygwin",
        reason="Cygwin can't set the permissions that make the test meaningful.",
    )
    def test_deletes_dir_with_readonly_files(self, tmp_path):
        # Automatically works on Unix, but requires special handling on Windows.
        # Not to be confused with what permission_error_tmpdir sets up (see below).

        td = tmp_path / "testdir"

        for d in td, td / "sub":
            d.mkdir()
        for f in td / "x", td / "sub" / "y":
            f.touch()
            f.chmod(0)

        try:
            rmtree(td)
        except SkipTest as ex:
            self.fail(f"rmtree unexpectedly attempts skip: {ex!r}")

        assert not td.exists()

    @pytest.mark.skipif(
        sys.platform == "cygwin",
        reason="Cygwin can't set the permissions that make the test meaningful.",
    )
    def test_avoids_changing_permissions_outside_tree(self, tmp_path):
        # Automatically works on Windows, but on Unix requires either special handling
        # or refraining from attempting to fix PermissionError by making chmod calls.

        dir1 = tmp_path / "dir1"
        dir1.mkdir()
        (dir1 / "file").touch()
        (dir1 / "file").chmod(stat.S_IRUSR)
        old_mode = (dir1 / "file").stat().st_mode

        dir2 = tmp_path / "dir2"
        dir2.mkdir()
        (dir2 / "symlink").symlink_to(dir1 / "file")
        dir2.chmod(stat.S_IRUSR | stat.S_IXUSR)

        try:
            rmtree(dir2)
        except PermissionError:
            pass  # On Unix, dir2 is not writable, so dir2/symlink may not be deleted.
        except SkipTest as ex:
            self.fail(f"rmtree unexpectedly attempts skip: {ex!r}")

        new_mode = (dir1 / "file").stat().st_mode
        assert old_mode == new_mode, f"Should stay {old_mode:#o}, became {new_mode:#o}."

    def _patch_for_wrapping_test(self, mocker, hide_windows_known_errors):
        # Access the module through sys.modules so it is unambiguous which module's
        # attribute we patch: the original git.util, not git.index.util even though
        # git.index.util "replaces" git.util and is what "import git.util" gives us.
        mocker.patch.object(sys.modules["git.util"], "HIDE_WINDOWS_KNOWN_ERRORS", hide_windows_known_errors)

        # Mock out common chmod functions to simulate PermissionError the callback can't
        # fix. (We leave the corresponding lchmod functions alone. If they're used, it's
        # more important we detect any failures from inadequate compatibility checks.)
        mocker.patch.object(os, "chmod")
        mocker.patch.object(pathlib.Path, "chmod")

    @pytest.mark.skipif(
        sys.platform != "win32",
        reason="PermissionError is only ever wrapped on Windows",
    )
    def test_wraps_perm_error_if_enabled(self, mocker, permission_error_tmpdir):
        """rmtree wraps PermissionError on Windows when HIDE_WINDOWS_KNOWN_ERRORS is
        true."""
        self._patch_for_wrapping_test(mocker, True)

        with pytest.raises(SkipTest):
            rmtree(permission_error_tmpdir)

    @pytest.mark.skipif(
        sys.platform == "cygwin",
        reason="Cygwin can't set the permissions that make the test meaningful.",
    )
    @pytest.mark.parametrize(
        "hide_windows_known_errors",
        [
            pytest.param(False),
            pytest.param(True, marks=pytest.mark.skipif(sys.platform == "win32", reason="We would wrap on Windows")),
        ],
    )
    def test_does_not_wrap_perm_error_unless_enabled(self, mocker, permission_error_tmpdir, hide_windows_known_errors):
        """rmtree does not wrap PermissionError on non-Windows systems or when
        HIDE_WINDOWS_KNOWN_ERRORS is false."""
        self._patch_for_wrapping_test(mocker, hide_windows_known_errors)

        with pytest.raises(PermissionError):
            try:
                rmtree(permission_error_tmpdir)
            except SkipTest as ex:
                pytest.fail(f"rmtree unexpectedly attempts skip: {ex!r}")

    @pytest.mark.parametrize("hide_windows_known_errors", [False, True])
    def test_does_not_wrap_other_errors(self, tmp_path, mocker, hide_windows_known_errors):
        # The file is deliberately never created.
        file_not_found_tmpdir = tmp_path / "testdir"

        self._patch_for_wrapping_test(mocker, hide_windows_known_errors)

        with pytest.raises(FileNotFoundError):
            try:
                rmtree(file_not_found_tmpdir)
            except SkipTest as ex:
                self.fail(f"rmtree unexpectedly attempts skip: {ex!r}")


class TestEnvParsing:
    """Tests for environment variable parsing logic in :mod:`git.util`."""

    @staticmethod
    def _run_parse(name, value):
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

    @pytest.mark.skipif(
        sys.platform != "win32",
        reason="These environment variables are only used on Windows.",
    )
    @pytest.mark.parametrize(
        "env_var_value, expected_truth_value",
        [
            (None, True),  # When the environment variable is unset.
            ("", False),
            (" ", False),
            ("0", False),
            ("1", True),
            ("false", False),
            ("true", True),
            ("False", False),
            ("True", True),
            ("no", False),
            ("yes", True),
            ("NO", False),
            ("YES", True),
            (" no  ", False),
            (" yes  ", True),
        ],
    )
    @pytest.mark.parametrize(
        "name",
        [
            "HIDE_WINDOWS_KNOWN_ERRORS",
            "HIDE_WINDOWS_FREEZE_ERRORS",
        ],
    )
    def test_env_vars_for_windows_tests(self, name, env_var_value, expected_truth_value):
        actual_parsed_value = self._run_parse(name, env_var_value)
        assert actual_parsed_value is expected_truth_value


def _xfail_param(*values, **xfail_kwargs):
    """Build a pytest.mark.parametrize parameter that carries an xfail mark."""
    return pytest.param(*values, marks=pytest.mark.xfail(**xfail_kwargs))


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
"""Path test cases for cygpath and decygpath, other than extended UNC paths."""

_unc_cygpath_pairs = (
    (R"\\?\a:\com", "/cygdrive/a/com"),
    (R"\\?\a:/com", "/cygdrive/a/com"),
    (R"\\?\UNC\server\D$\Apps", "//server/D$/Apps"),
)
"""Extended UNC path test cases for cygpath."""

_cygpath_ok_xfails = {
    # From _norm_cygpath_pairs:
    (R"C:\Users", "/cygdrive/c/Users"): "/proc/cygdrive/c/Users",
    (R"C:\d/e", "/cygdrive/c/d/e"): "/proc/cygdrive/c/d/e",
    ("C:\\", "/cygdrive/c/"): "/proc/cygdrive/c/",
    (R"\\server\BAR/", "//server/BAR/"): "//server/BAR",
    (R"D:/Apps", "/cygdrive/d/Apps"): "/proc/cygdrive/d/Apps",
    (R"D:/Apps\fOO", "/cygdrive/d/Apps/fOO"): "/proc/cygdrive/d/Apps/fOO",
    (R"D:\Apps/123", "/cygdrive/d/Apps/123"): "/proc/cygdrive/d/Apps/123",
    # From _unc_cygpath_pairs:
    (R"\\?\a:\com", "/cygdrive/a/com"): "/proc/cygdrive/a/com",
    (R"\\?\a:/com", "/cygdrive/a/com"): "/proc/cygdrive/a/com",
}
"""Mapping of expected failures for the test_cygpath_ok test."""


_cygpath_ok_params = [
    (
        _xfail_param(*case, reason=f"Returns: {_cygpath_ok_xfails[case]!r}", raises=AssertionError)
        if case in _cygpath_ok_xfails
        else case
    )
    for case in _norm_cygpath_pairs + _unc_cygpath_pairs
]
"""Parameter sets for the test_cygpath_ok test."""


@pytest.mark.skipif(sys.platform != "cygwin", reason="Paths specifically for Cygwin.")
class TestCygpath:
    """Tests for :func:`git.util.cygpath` and :func:`git.util.decygpath`."""

    @pytest.mark.parametrize("wpath, cpath", _cygpath_ok_params)
    def test_cygpath_ok(self, wpath, cpath):
        cwpath = cygpath(wpath)
        assert cwpath == cpath, wpath

    @pytest.mark.parametrize(
        "wpath, cpath",
        [
            (R"./bar", "bar"),
            _xfail_param(R".\bar", "bar", reason="Returns: './bar'", raises=AssertionError),
            (R"../bar", "../bar"),
            (R"..\bar", "../bar"),
            (R"../bar/.\foo/../chu", "../bar/chu"),
        ],
    )
    def test_cygpath_norm_ok(self, wpath, cpath):
        cwpath = cygpath(wpath)
        assert cwpath == (cpath or wpath), wpath

    @pytest.mark.parametrize(
        "wpath",
        [
            R"C:",
            R"C:Relative",
            R"D:Apps\123",
            R"D:Apps/123",
            R"\\?\a:rel",
            R"\\share\a:rel",
        ],
    )
    def test_cygpath_invalids(self, wpath):
        cwpath = cygpath(wpath)
        assert cwpath == wpath.replace("\\", "/"), wpath

    @pytest.mark.parametrize("wpath, cpath", _norm_cygpath_pairs)
    def test_decygpath(self, wpath, cpath):
        wcpath = decygpath(cpath)
        assert wcpath == wpath.replace("/", "\\"), cpath


class _Member:
    """A member of an IterableList."""

    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f"{type(self).__name__}({self.name!r})"


@ddt.ddt
class TestUtils(TestBase):
    """Tests for most utilities in :mod:`git.util`."""

    def test_it_should_dashify(self):
        self.assertEqual("this-is-my-argument", dashify("this_is_my_argument"))
        self.assertEqual("foo", dashify("foo"))

    def test_lock_file(self):
        with tempfile.TemporaryDirectory() as tdir:
            my_file = os.path.join(tdir, "my-lock-file")
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
        with tempfile.TemporaryDirectory() as tdir:
            my_file = os.path.join(tdir, "my-lock-file")
            lock_file = BlockingLockFile(my_file)
            lock_file._obtain_lock()

            # Next one waits for the lock.
            start = time.time()
            wait_time = 0.1
            wait_lock = BlockingLockFile(my_file, 0.05, wait_time)
            self.assertRaises(IOError, wait_lock._obtain_lock)
            elapsed = time.time() - start

        extra_time = 0.02
        if sys.platform in {"win32", "cygwin"}:
            extra_time *= 6  # Without this, we get indeterministic failures on Windows.
        elif sys.platform == "darwin":
            extra_time *= 18  # The situation on macOS is similar, but with more delay.

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
        # depends on whether the user running the test has their global user.name config
        # set.
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
