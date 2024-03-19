# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

from git import Actor

from test.lib import TestBase


class TestActor(TestBase):
    def test_from_string_should_separate_name_and_email(self):
        a = Actor._from_string("Michael Trier <mtrier@example.com>")
        self.assertEqual("Michael Trier", a.name)
        self.assertEqual("mtrier@example.com", a.email)

        # Base type capabilities
        assert a == a
        assert not (a != a)
        m = set()
        m.add(a)
        m.add(a)
        assert len(m) == 1

    def test_from_string_should_handle_just_name(self):
        a = Actor._from_string("Michael Trier")
        self.assertEqual("Michael Trier", a.name)
        self.assertEqual(None, a.email)

    def test_should_display_representation(self):
        a = Actor._from_string("Michael Trier <mtrier@example.com>")
        self.assertEqual('<git.Actor "Michael Trier <mtrier@example.com>">', repr(a))

    def test_str_should_alias_name(self):
        a = Actor._from_string("Michael Trier <mtrier@example.com>")
        self.assertEqual(a.name, str(a))
