# test_diff.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from git.test.lib import *
from git import *

class TestDiff(TestBase):
			
	def _assert_diff_format(self, diffs):
		# verify that the format of the diff is sane
		for diff in diffs:
			if diff.a_mode:
				assert isinstance(diff.a_mode, int)
			if diff.b_mode:
				assert isinstance(diff.b_mode, int)
				
			if diff.a_blob:
				assert not diff.a_blob.path.endswith('\n')
			if diff.b_blob:
				assert not diff.b_blob.path.endswith('\n')
		# END for each diff
		return diffs
	
	def test_list_from_string_new_mode(self):
		output = StringProcessAdapter(fixture('diff_new_mode'))
		diffs = Diff._index_from_patch_format(self.rorepo, output.stdout)
		self._assert_diff_format(diffs)
		
		assert_equal(1, len(diffs))
		assert_equal(10, len(diffs[0].diff.splitlines()))

	def test_diff_with_rename(self):
		output = StringProcessAdapter(fixture('diff_rename'))
		diffs = Diff._index_from_patch_format(self.rorepo, output.stdout)
		self._assert_diff_format(diffs)
		
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
			diff_proc = StringProcessAdapter(fixture(fixture_name))
			diffs = Diff._index_from_patch_format(self.rorepo, diff_proc.stdout)
		# END for each fixture

	def test_diff_interface(self):
		# test a few variations of the main diff routine
		assertion_map = dict()
		for i, commit in enumerate(self.rorepo.iter_commits('0.1.6', max_count=2)):
			diff_item = commit
			if i%2 == 0:
				diff_item = commit.tree
			# END use tree every second item
			
			for other in (None, commit.Index, commit.parents[0]):
				for paths in (None, "CHANGES", ("CHANGES", "lib")):
					for create_patch in range(2):
						diff_index = diff_item.diff(other, paths, create_patch)
						assert isinstance(diff_index, DiffIndex)
						
						if diff_index:
							self._assert_diff_format(diff_index)
							for ct in DiffIndex.change_type:
								key = 'ct_%s'%ct
								assertion_map.setdefault(key, 0)
								assertion_map[key] = assertion_map[key]+len(list(diff_index.iter_change_type(ct)))	
							# END for each changetype
							
							# check entries
							diff_set = set()
							diff_set.add(diff_index[0])
							diff_set.add(diff_index[0])
							assert len(diff_set) == 1
							assert diff_index[0] == diff_index[0]
							assert not (diff_index[0] != diff_index[0])
						# END diff index checking 
					# END for each patch option
				# END for each path option
			# END for each other side
		# END for each commit
		
		# assert we could always find at least one instance of the members we 
		# can iterate in the diff index - if not this indicates its not working correctly
		# or our test does not span the whole range of possibilities
		for key,value in assertion_map.items():
			assert value, "Did not find diff for %s" % key
		# END for each iteration type 
		
		# test path not existing in the index - should be ignored
		c = self.rorepo.head.commit
		cp = c.parents[0]
		diff_index = c.diff(cp, ["does/not/exist"])
		assert len(diff_index) == 0
		
	
