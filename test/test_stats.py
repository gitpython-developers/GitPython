# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

from git import Stats
from git.compat import defenc

from test.lib import TestBase, fixture


class TestStats(TestBase):
    def test_list_from_string(self):
        output = fixture("diff_numstat").decode(defenc)
        stats = Stats._list_from_string(self.rorepo, output)

        self.assertEqual(3, stats.total["files"])
        self.assertEqual(59, stats.total["lines"])
        self.assertEqual(36, stats.total["insertions"])
        self.assertEqual(23, stats.total["deletions"])

        self.assertEqual(29, stats.files["a.txt"]["insertions"])
        self.assertEqual(18, stats.files["a.txt"]["deletions"])
        self.assertEqual("M", stats.files["a.txt"]["change_type"])

        self.assertEqual(0, stats.files["b.txt"]["insertions"])
        self.assertEqual(5, stats.files["b.txt"]["deletions"])
        self.assertEqual("M", stats.files["b.txt"]["change_type"])

        self.assertEqual(7, stats.files["c.txt"]["insertions"])
        self.assertEqual(0, stats.files["c.txt"]["deletions"])
        self.assertEqual("A", stats.files["c.txt"]["change_type"])
