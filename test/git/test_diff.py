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

	def test_diff_patch_format(self):
		# test all of the 'old' format diffs for completness - it should at least
		# be able to deal with it
		fixtures = ("diff_2", "diff_2f", "diff_f", "diff_i", "diff_mode_only", 
					"diff_new_mode", "diff_numstat", "diff_p", "diff_rename", 
					"diff_tree_numstat_root" )
		
		for fixture_name in fixtures:
			diff_proc = ListProcessAdapter(fixture(fixture_name))
			diffs = Diff._index_from_patch_format(self.repo, diff_proc.stdout)
		# END for each fixture

	def test_diff_interface(self):
		# test a few variations of the main diff routine
		for i, commit in enumerate(self.repo.iter_commits('0.1.6', max_count=10)):
			diff_item = commit
			if i%2 == 0:
				diff_item = commit.tree
			# END use tree every second item
			
			for other in (None, commit.parents[0]):
				for paths in (None, "CHANGES", ("CHANGES", "lib")):
					for create_patch in range(2):
						diff_index = diff_item.diff(other, paths, create_patch)
						assert diff_index
					# END for each patch option
				# END for each path option
			# END for each other side
		# END for each commit
		
		
		self.fail( "TODO: Test full diff interface on commits, trees, index, patch and non-patch" )
