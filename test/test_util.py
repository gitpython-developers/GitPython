# test_utils.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import pickle
import sys
import tempfile
import time
from unittest import mock, skipIf
from datetime import datetime

import pytest
import ddt

from git.cmd import dashify
from git.compat import is_win
from git.objects.util import (
    altz_to_utctz_str,
    utctz_to_altz,
    verify_utctz,
    parse_date,
    tzoffset,
    from_timestamp,
)
from test.lib import (
    TestBase,
    with_rw_repo,
)
from git.util import (
    LockFile,
    BlockingLockFile,
    get_user_id,
    Actor,
    IterableList,
    cygpath,
    decygpath,
    remove_password_if_present,
)


_norm_cygpath_pairs = (
    (r"foo\bar", "foo/bar"),
    (r"foo/bar", "foo/bar"),
    (r"C:\Users", "/cygdrive/c/Users"),
    (r"C:\d/e", "/cygdrive/c/d/e"),
    ("C:\\", "/cygdrive/c/"),
    (r"\\server\C$\Users", "//server/C$/Users"),
    (r"\\server\C$", "//server/C$"),
    ("\\\\server\\c$\\", "//server/c$/"),
    (r"\\server\BAR/", "//server/BAR/"),
    (r"D:/Apps", "/cygdrive/d/Apps"),
    (r"D:/Apps\fOO", "/cygdrive/d/Apps/fOO"),
    (r"D:\Apps/123", "/cygdrive/d/Apps/123"),
)

_unc_cygpath_pairs = (
    (r"\\?\a:\com", "/cygdrive/a/com"),
    (r"\\?\a:/com", "/cygdrive/a/com"),
    (r"\\?\UNC\server\D$\Apps", "//server/D$/Apps"),
)


class TestIterableMember(object):

    """A member of an iterable list"""

    __slots__ = "name"

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "TestIterableMember(%r)" % self.name


@ddt.ddt
class TestUtils(TestBase):
    def setup(self):
        self.testdict = {
            "string": "42",
            "int": 42,
            "array": [42],
        }

    @skipIf(not is_win, "Paths specifically for Windows.")
    @ddt.idata(_norm_cygpath_pairs + _unc_cygpath_pairs)
    def test_cygpath_ok(self, case):
        wpath, cpath = case
        cwpath = cygpath(wpath)
        self.assertEqual(cwpath, cpath, wpath)

    @skipIf(not is_win, "Paths specifically for Windows.")
    @ddt.data(
        (r"./bar", "bar"),
        (r".\bar", "bar"),
        (r"../bar", "../bar"),
        (r"..\bar", "../bar"),
        (r"../bar/.\foo/../chu", "../bar/chu"),
    )
    def test_cygpath_norm_ok(self, case):
        wpath, cpath = case
        cwpath = cygpath(wpath)
        self.assertEqual(cwpath, cpath or wpath, wpath)

    @skipIf(not is_win, "Paths specifically for Windows.")
    @ddt.data(
        r"C:",
        r"C:Relative",
        r"D:Apps\123",
        r"D:Apps/123",
        r"\\?\a:rel",
        r"\\share\a:rel",
    )
    def test_cygpath_invalids(self, wpath):
        cwpath = cygpath(wpath)
        self.assertEqual(cwpath, wpath.replace("\\", "/"), wpath)

    @skipIf(not is_win, "Paths specifically for Windows.")
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
        # release lock we don't have  - fine
        lock_file._release_lock()

        # get lock
        lock_file._obtain_lock_or_raise()
        assert lock_file._has_lock()

        # concurrent access
        other_lock_file = LockFile(my_file)
        assert not other_lock_file._has_lock()
        self.assertRaises(IOError, other_lock_file._obtain_lock_or_raise)

        lock_file._release_lock()
        assert not lock_file._has_lock()

        other_lock_file._obtain_lock_or_raise()
        self.assertRaises(IOError, lock_file._obtain_lock_or_raise)

        # auto-release on destruction
        del other_lock_file
        lock_file._obtain_lock_or_raise()
        lock_file._release_lock()

    @pytest.mark.xfail(
        sys.platform == "cygwin",
        reason="Cygwin fails here for some reason, always",
        raises=AssertionError
    )
    def test_blocking_lock_file(self):
        my_file = tempfile.mktemp()
        lock_file = BlockingLockFile(my_file)
        lock_file._obtain_lock()

        # next one waits for the lock
        start = time.time()
        wait_time = 0.1
        wait_lock = BlockingLockFile(my_file, 0.05, wait_time)
        self.assertRaises(IOError, wait_lock._obtain_lock)
        elapsed = time.time() - start
        extra_time = 0.02
        if is_win:
            # for Appveyor
            extra_time *= 6  # NOTE: Indeterministic failures here...
        self.assertLess(elapsed, wait_time + extra_time)

    def test_user_id(self):
        self.assertIn("@", get_user_id())

    def test_parse_date(self):
        # parse_date(from_timestamp()) must return the tuple unchanged
        for timestamp, offset in (
            (1522827734, -7200),
            (1522827734, 0),
            (1522827734, +3600),
        ):
            self.assertEqual(parse_date(from_timestamp(timestamp, offset)), (timestamp, offset))

        # test all supported formats
        def assert_rval(rval, veri_time, offset=0):
            self.assertEqual(len(rval), 2)
            self.assertIsInstance(rval[0], int)
            self.assertIsInstance(rval[1], int)
            self.assertEqual(rval[0], veri_time)
            self.assertEqual(rval[1], offset)

            # now that we are here, test our conversion functions as well
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
        veri_time_utc = 1112911991  # the time this represents, in time since epoch, UTC
        for date, offset in (rfc, iso, iso2, iso3, alt, alt2):
            assert_rval(parse_date(date), veri_time_utc, offset)
        # END for each date type

        # and failure
        self.assertRaises(ValueError, parse_date, datetime.now())  # non-aware datetime
        self.assertRaises(ValueError, parse_date, "invalid format")
        self.assertRaises(ValueError, parse_date, "123456789 -02000")
        self.assertRaises(ValueError, parse_date, " 123456789 -0200")

    def test_actor(self):
        for cr in (None, self.rorepo.config_reader()):
            self.assertIsInstance(Actor.committer(cr), Actor)
            self.assertIsInstance(Actor.author(cr), Actor)
        # END assure config reader is handled

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
        # We can't test with `self.rorepo.config_reader()` here, as the uuid laziness
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

    @ddt.data(("name", ""), ("name", "prefix_"))
    def test_iterable_list(self, case):
        name, prefix = case
        ilist = IterableList(name, prefix)

        name1 = "one"
        name2 = "two"
        m1 = TestIterableMember(prefix + name1)
        m2 = TestIterableMember(prefix + name2)

        ilist.extend((m1, m2))

        self.assertEqual(len(ilist), 2)

        # contains works with name and identity
        self.assertIn(name1, ilist)
        self.assertIn(name2, ilist)
        self.assertIn(m2, ilist)
        self.assertIn(m2, ilist)
        self.assertNotIn("invalid", ilist)

        # with string index
        self.assertIs(ilist[name1], m1)
        self.assertIs(ilist[name2], m2)

        # with int index
        self.assertIs(ilist[0], m1)
        self.assertIs(ilist[1], m2)

        # with getattr
        self.assertIs(ilist.one, m1)
        self.assertIs(ilist.two, m2)

        # test exceptions
        self.assertRaises(AttributeError, getattr, ilist, "something")
        self.assertRaises(IndexError, ilist.__getitem__, "something")

        # delete by name and index
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

    def test_from_timestamp(self):
        # Correct offset: UTC+2, should return datetime + tzoffset(+2)
        altz = utctz_to_altz("+0200")
        self.assertEqual(
            datetime.fromtimestamp(1522827734, tzoffset(altz)),
            from_timestamp(1522827734, altz),
        )

        # Wrong offset: UTC+58, should return datetime + tzoffset(UTC)
        altz = utctz_to_altz("+5800")
        self.assertEqual(
            datetime.fromtimestamp(1522827734, tzoffset(0)),
            from_timestamp(1522827734, altz),
        )

        # Wrong offset: UTC-9000, should return datetime + tzoffset(UTC)
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
        # Check that we use a copy
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
