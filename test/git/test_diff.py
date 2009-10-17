# test_diff.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *

class TestDiff(TestCase):
	def setUp(self):
		self.repo = Repo(GIT_REPO)

	def test_list_from_string_new_mode(self):
		output = ListProcessAdapter(fixture('diff_new_mode'))
		diffs = Diff._index_from_patch_format(self.repo, output.stdout)
		assert_equal(1, len(diffs))
		assert_equal(10, len(diffs[0].diff.splitlines()))

	def test_diff_with_rename(self):
		output = ListProcessAdapter(fixture('diff_rename'))
		diffs = Diff._index_from_patch_format(self.repo, output.stdout)

		assert_equal(1, len(diffs))

		diff = diffs[0]
		assert_true(diff.renamed)
		assert_equal(diff.rename_from, 'AUTHORS')
		assert_equal(diff.rename_to, 'CONTRIBUTORS')

	def test_diff_interface(self):
		self.fail( "TODO: Test full diff interface on commits, trees, index, patch and non-patch" )
