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

    def test_from_string_handles_unterminated_email_without_regex_backtracking(self):
        value = "A" * 20_000 + " <unterminated"
        actor = Actor._from_string(value)
        self.assertNotIn("name_email_regex", vars(Actor))
        self.assertEqual(actor, Actor(value, None))

    def test_from_string_does_not_parse_across_lines(self):
        self.assertEqual(Actor._from_string("x <a>\n y <b>"), Actor("x", "a"))

    def test_from_string_uses_git_delimiters(self):
        for value, expected in (
            ("Name <e<mail>", Actor("Name", "e<mail")),
            ("Name <email>>", Actor("Name", "email")),
            ("Name<email>", Actor("Name", "email")),
            (" <>", Actor("", "")),
            ("Name <email", Actor("Name <email", None)),
            ("Name email>", Actor("Name email>", None)),
        ):
            self.assertEqual(Actor._from_string(value), expected)

    def test_should_display_representation(self):
        a = Actor._from_string("Michael Trier <mtrier@example.com>")
        self.assertEqual('<git.Actor "Michael Trier <mtrier@example.com>">', repr(a))

    def test_str_should_alias_name(self):
        a = Actor._from_string("Michael Trier <mtrier@example.com>")
        self.assertEqual(a.name, str(a))
