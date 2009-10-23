# test_commit.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *

class TestCommit(TestBase):

	def test_bake(self):

		commit = Commit(self.rorepo, **{'id': '2454ae89983a4496a445ce347d7a41c0bb0ea7ae'})
		commit.author # bake

		assert_equal("Sebastian Thiel", commit.author.name)
		assert_equal("byronimo@gmail.com", commit.author.email)
		assert commit.author == commit.committer
		assert isinstance(commit.authored_date, int) and isinstance(commit.committed_date, int)
		assert commit.message == "Added missing information to docstrings of commit and stats module"


	def test_stats(self):
		commit = Commit(self.rorepo, id='33ebe7acec14b25c5f84f35a664803fcab2f7781')
		stats = commit.stats
		
		def check_entries(d):
			assert isinstance(d, dict)
			for key in ("insertions", "deletions", "lines"):
				assert key in d
		# END assertion helper 
		assert stats.files 
		assert stats.total
		
		check_entries(stats.total) 
		assert "files" in stats.total
		
		for filepath, d in stats.files.items():
			check_entries(d)
		# END for each stated file
		
		# assure data is parsed properly
		michael = Actor._from_string("Michael Trier <mtrier@gmail.com>")
		assert commit.author == michael
		assert commit.committer == michael
		assert commit.authored_date == 1210193388
		assert commit.committed_date == 1210193388
		assert commit.message == "initial project"
		
	@patch_object(Git, '_call_process')
	def test_rev_list_bisect_all(self, git):
		"""
		'git rev-list --bisect-all' returns additional information
		in the commit header.  This test ensures that we properly parse it.
		"""

		git.return_value = fixture('rev_list_bisect_all')

		revs = self.rorepo.git.rev_list('HEAD',
									  pretty='raw',
									  first_parent=True,
									  bisect_all=True)
		assert_true(git.called)

		commits = Commit._iter_from_process_or_stream(self.rorepo, ListProcessAdapter(revs), True)
		expected_ids = (
			'cf37099ea8d1d8c7fbf9b6d12d7ec0249d3acb8b',
			'33ebe7acec14b25c5f84f35a664803fcab2f7781',
			'a6604a00a652e754cb8b6b0b9f194f839fc38d7c',
			'8df638c22c75ddc9a43ecdde90c0c9939f5009e7',
			'c231551328faa864848bde6ff8127f59c9566e90',
		)
		for sha1, commit in zip(expected_ids, commits):
			assert_equal(sha1, commit.id)

	def test_count(self):
		assert self.rorepo.tag('refs/tags/0.1.5').commit.count( ) == 141
		
	def test_list(self):
		assert isinstance(Commit.list_items(self.rorepo, '0.1.5', max_count=5)['5117c9c8a4d3af19a9958677e45cda9269de1541'], Commit)

	def test_str(self):
		commit = Commit(self.rorepo, id='abc')
		assert_equal ("abc", str(commit))

	def test_repr(self):
		commit = Commit(self.rorepo, id='abc')
		assert_equal('<git.Commit "abc">', repr(commit))

	def test_equality(self):
		commit1 = Commit(self.rorepo, id='abc')
		commit2 = Commit(self.rorepo, id='abc')
		commit3 = Commit(self.rorepo, id='zyx')
		assert_equal(commit1, commit2)
		assert_not_equal(commit2, commit3)
		
	def test_iter_parents(self):
		# should return all but ourselves, even if skip is defined
		c = self.rorepo.commit('0.1.5')
		for skip in (0, 1):
			piter = c.iter_parents(skip=skip)
			first_parent = piter.next()
			assert first_parent != c
			assert first_parent == c.parents[0]
		# END for each 
		
