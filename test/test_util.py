# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import contextlib
from datetime import datetime
import os
import pickle
import stat
import sys
import threading
import time
from unittest import SkipTest, mock

import ddt
import pytest

from git.cmd import dashify
from git.objects.util import (
    altz_to_utctz_str,
    from_timestamp,
    mode_str_to_int,
    parse_actor_and_date,
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
    is_cygwin_git,
    get_user_id,
    remove_password_if_present,
    rmtree,
)

from test.cleanup import TemporaryDirectory, cleanup_directory
from test.lib import TestBase, requires_symlinks, with_rw_repo


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
    @requires_symlinks
    def test_avoids_changing_permissions_outside_tree(self, tmp_path, request):
        # Automatically works on Windows, but on Unix requires either special handling
        # or refraining from attempting to fix PermissionError by making chmod calls.

        dir1 = tmp_path / "dir1"
        dir1.mkdir()
        (dir1 / "file").touch()
        (dir1 / "file").chmod(stat.S_IRUSR)
        old_mode = (dir1 / "file").stat().st_mode

        dir2 = tmp_path / "dir2"
        dir2.mkdir()
        symlink = dir2 / "symlink"
        symlink.symlink_to(dir1 / "file")
        dir2.chmod(stat.S_IRUSR | stat.S_IXUSR)

        def preen_dir2():
            """Don't leave unwritable directories behind.

            pytest has difficulties cleaning up after the fact on some platforms,
            e.g., macOS, and whines incessantly until the issue is resolved--regardless
            of the pytest session.
            """
            rwx = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
            if not dir2.exists():
                return
            with contextlib.suppress(OSError):
                if symlink.exists():
                    try:
                        # Try lchmod first, if the platform supports it.
                        symlink.lchmod(rwx)
                    except NotImplementedError:
                        # The platform (probably win32) doesn't support lchmod; fall back to chmod.
                        symlink.chmod(rwx)
                dir2.chmod(rwx)
            cleanup_directory(dir2)

        request.addfinalizer(preen_dir2)

        try:
            rmtree(dir2)
        except PermissionError:
            pass  # On Unix, dir2 is not writable, so dir2/symlink may not be deleted.
        except SkipTest as ex:
            self.fail(f"rmtree unexpectedly attempts skip: {ex!r}")

        new_mode = (dir1 / "file").stat().st_mode
        assert old_mode == new_mode, f"Should stay {old_mode:#o}, became {new_mode:#o}."


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


class TestIsCygwinGit:
    """Tests for :func:`is_cygwin_git`"""

    def test_on_path_executable(self):
        # Currently we assume tests run on Cygwin use Cygwin git. See #533 and #1455 for background.
        if sys.platform == "cygwin":
            assert is_cygwin_git("git")
        else:
            assert not is_cygwin_git("git")

    def test_none_executable(self):
        assert not is_cygwin_git(None)

    def test_with_missing_uname(self):
        """Test for handling when `uname` isn't in the same directory as `git`"""
        assert not is_cygwin_git("/bogus_path/git")


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

    @pytest.mark.skipif(os.name != "nt", reason="Specifically for Windows drive-rooted paths.")
    def test_cygpath_drive_rooted_path(self):
        assert cygpath(R"\directory\file") == "/directory/file"

    def test_it_should_dashify(self):
        self.assertEqual("this-is-my-argument", dashify("this_is_my_argument"))
        self.assertEqual("foo", dashify("foo"))

    @ddt.data("my-lock-file", "my-lock-file-\u0394", "\u0394/my-lock-file", "\U0001f680/my-lock-file")
    def test_lock_file(self, filename):
        with TemporaryDirectory() as tdir:
            my_file = os.path.join(tdir, filename)
            os.makedirs(os.path.dirname(my_file), exist_ok=True)
            lock_file = LockFile(my_file)
            assert not lock_file._has_lock()
            # Release lock we don't have - fine.
            lock_file._release_lock()

            # Get lock.
            lock_file._obtain_lock_or_raise()
            assert lock_file._has_lock()
            assert os.path.isfile(my_file + ".lock")

            # Concurrent access.
            other_lock_file = LockFile(my_file)
            assert not other_lock_file._has_lock()
            self.assertRaises(IOError, other_lock_file._obtain_lock_or_raise)

            lock_file._release_lock()
            assert not lock_file._has_lock()
            assert not os.path.exists(my_file + ".lock")

            other_lock_file._obtain_lock_or_raise()
            self.assertRaises(IOError, lock_file._obtain_lock_or_raise)

            # Auto-release on destruction.
            del other_lock_file
            lock_file._obtain_lock_or_raise()
            lock_file._release_lock()

    def test_lock_file_rejects_embedded_nul(self):
        with TemporaryDirectory() as tdir:
            my_file = os.path.join(tdir, "my-lock-file")
            lock_file = LockFile(my_file + "\0suffix")
            self.assertRaises(ValueError, lock_file._obtain_lock_or_raise)
            assert not lock_file._has_lock()
            assert not os.path.exists(my_file)

    @ddt.data(False, True)
    @requires_symlinks
    def test_lock_file_does_not_follow_a_symlink(self, target_exists):
        with TemporaryDirectory() as tdir:
            my_file = os.path.join(tdir, "my-lock-file")
            outside = os.path.join(tdir, "outside-the-lock")
            content = b"Do not modify the symlink target."
            if target_exists:
                with open(outside, "wb") as stream:
                    stream.write(content)
            os.symlink(outside, my_file + ".lock")

            lock_file = LockFile(my_file)
            self.assertRaises(IOError, lock_file._obtain_lock_or_raise)
            assert not lock_file._has_lock()
            lock_file._release_lock()
            assert os.path.islink(my_file + ".lock")
            if target_exists:
                with open(outside, "rb") as stream:
                    self.assertEqual(stream.read(), content)
            else:
                assert not os.path.exists(outside)

    def test_lock_file_is_obtained_by_a_single_holder(self):
        with TemporaryDirectory() as tdir:
            my_file = os.path.join(tdir, "my-lock-file")
            racers = 8
            at_the_line = threading.Barrier(racers)
            holders = []
            guard = threading.Lock()

            def obtain():
                lock_file = LockFile(my_file)
                at_the_line.wait()
                try:
                    lock_file._obtain_lock_or_raise()
                except OSError:
                    return
                with guard:
                    holders.append(lock_file)

            threads = [threading.Thread(target=obtain) for _ in range(racers)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            try:
                self.assertEqual(1, len(holders))
            finally:
                for lock_file in holders:
                    lock_file._release_lock()

    def test_blocking_lock_file(self):
        with TemporaryDirectory() as tdir:
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
        alt = ("04/07/2005 22:13:11 +0000", 0)
        alt2 = ("07.04.2005 22:13:11 +0000", 0)
        veri_time_utc = 1112911991  # The time this represents, in time since epoch, UTC.
        for date, offset in (rfc, iso, iso2, iso3, alt, alt2):
            assert_rval(parse_date(date), veri_time_utc + offset, offset)
        # END for each date type

        # ...and failure.
        self.assertRaises(ValueError, parse_date, datetime.now())  # Non-aware datetime.
        self.assertRaises(ValueError, parse_date, "invalid format")
        assert parse_date(" 123456789 -0200") == (123456789, 7200)

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
        ("", Actor("", None), 0, 0),
        ("author", Actor("author", None), 0, 0),
        ("author Name <email> 42 -0700", Actor("Name", "email"), 42, 25200),
        ("committer Name <email> 42 +0530\n", Actor("Name", "email"), 42, -19800),
        ("tagger Name <email> 42 +0000\r\n", Actor("Name", "email"), 42, 0),
        ("author Name <email> 42 -0700 trailing", Actor("Name", "email"), 42, 25200),
        ("author Name <email> 1 +0 42 -0700", Actor("Name", "email"), 42, 25200),
        ("author Name <email> invalid -0700", Actor("Name", "email"), 0, 0),
        ("author Name <email> 42 invalid", Actor("Name", "email"), 0, 0),
        ("author 42 -0700", Actor("42 -0700", None), 0, 0),
        ("author  42 -0700", Actor("", None), 42, 25200),
        (" author Name <email> 42 -0700", Actor("Name", "email"), 42, 25200),
        ("author Näme <email> ١ +٠١٣٠", Actor("Näme", "email"), 1, -5400),
        ("author\nName <email> 42 -0700", Actor("author\nName <email> 42 -0700", None), 0, 0),
        ("author Name <email> 42 -0700\nextra", Actor("author Name", "email"), 0, 0),
    )
    @ddt.unpack
    def test_parse_actor_and_date(self, line, actor, epoch, offset):
        self.assertEqual(parse_actor_and_date(line), (actor, epoch, offset))

    def test_parse_actor_and_date_long_malformed_lines(self):
        padding = " " * 64_000
        for field in ("author", "committer", "tagger"):
            for tail in ("", "<unterminated", "invalid -0700", "42", "-0700", "42 invalid", "42 +"):
                actor_text = padding + tail
                start = time.process_time()
                result = parse_actor_and_date(f"{field} {actor_text}")
                elapsed = time.process_time() - start
                # Leave ample CPU time for slow runners, but catch excessive backtracking.
                self.assertLess(elapsed, 1.0, (field, tail))
                self.assertEqual(result, (Actor(actor_text, None), 0, 0))

            name = "Long name " * 6_400
            self.assertEqual(
                parse_actor_and_date(f"{field} {name}<email> 42 -0700"),
                (Actor(name.rstrip(), "email"), 42, 25200),
            )

    def test_parse_actor_and_date_long_multiline_input(self):
        for field in ("author", "committer", "tagger"):
            line = f"{field} Name <email> 42 +" + "0" * 64_000 + "\nextra"
            start = time.process_time()
            result = parse_actor_and_date(line)
            elapsed = time.process_time() - start
            self.assertLess(elapsed, 1.0, field)
            self.assertEqual(result, (Actor(f"{field} Name", "email"), 0, 0))

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
        authorization = "Bearer fake-token-1234"
        url_with_user_and_pass = "https://{}:{}@fakerepo.example.com/testrepo".format(username, password)
        url_with_user = "https://{}@fakerepo.example.com/testrepo".format(username)
        url_with_pass = "https://:{}@fakerepo.example.com/testrepo".format(password)
        url_without_user_or_pass = "https://fakerepo.example.com/testrepo"

        cmd_1 = ["git", "clone", "-v", url_with_user_and_pass]
        cmd_2 = ["git", "clone", "-v", url_with_user]
        cmd_3 = ["git", "clone", "-v", url_with_pass]
        cmd_4 = ["git", "clone", "-v", url_without_user_or_pass]
        cmd_5 = ["no", "url", "in", "this", "one"]
        cmd_6 = ["git", "-c", "http.extraHeader=Authorization: %s" % authorization, "fetch"]

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

        redacted_cmd_6 = remove_password_if_present(cmd_6)
        assert authorization not in " ".join(redacted_cmd_6)
        assert "http.extraHeader=Authorization: *****" in redacted_cmd_6

    def test_remove_password_keeps_host_intact(self):
        """Redaction must not touch the host, even when it contains the username."""
        redacted = remove_password_if_present(["git", "clone", "https://git@github.com/user/repo.git"])
        assert redacted == ["git", "clone", "https://*****@github.com/user/repo.git"]

        redacted = remove_password_if_present(["git", "clone", "ssh://git@github.com/u/r.git"])
        assert redacted == ["git", "clone", "ssh://*****@github.com/u/r.git"]

    def test_remove_empty_password_keeps_host_intact(self):
        """An empty password must not expand into every position of the netloc."""
        redacted = remove_password_if_present(["git", "clone", "https://:@fakerepo.example.com/testrepo"])
        assert redacted == ["git", "clone", "https://*****:*****@fakerepo.example.com/testrepo"]

    @ddt.data(
        (
            "https://user%40example.com:p%40ss@GitHub.COM:00443/repo@name?q=a@b#c@d",
            "https://*****:*****@GitHub.COM:00443/repo@name?q=a@b#c@d",
        ),
        ("//user:pass@[2001:db8::1]:0080/repo", "//*****:*****@[2001:db8::1]:0080/repo"),
        ("https://user:p@ss@example.com/repo", "https://*****:*****@example.com/repo"),
        ("https://user:@example.com/repo", "https://*****:*****@example.com/repo"),
        ("https://@example.com/repo", "https://*****@example.com/repo"),
        ("https://example.com/repo@name?q=a@b#c@d", "https://example.com/repo@name?q=a@b#c@d"),
    )
    @ddt.unpack
    def test_remove_password_preserves_url_components(self, url, expected):
        assert remove_password_if_present([url]) == [expected]


def test_mode_str_to_int_accepts_bytes():
    assert mode_str_to_int("100644") == 0o100644
    assert mode_str_to_int(b"100644") == 0o100644
    assert mode_str_to_int("644") == 0o644
    assert mode_str_to_int(b"120000") == 0o120000
