# -*- coding: utf-8 -*-
# test_commit.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from git.test.lib import *
from git import *
from gitdb import IStream
from gitdb.util import hex_to_bin

from cStringIO import StringIO
import time
import sys


def assert_commit_serialization(rwrepo, commit_id, print_performance_info=False):
	"""traverse all commits in the history of commit identified by commit_id and check 
	if the serialization works.
	:param print_performance_info: if True, we will show how fast we are"""
	ns = 0		# num serializations
	nds = 0		# num deserializations
	
	st = time.time()
	for cm in rwrepo.commit(commit_id).traverse():
		nds += 1
		
		# assert that we deserialize commits correctly, hence we get the same 
		# sha on serialization
		stream = StringIO()
		cm._serialize(stream)
		ns += 1
		streamlen = stream.tell()
		stream.seek(0)
		
		istream = rwrepo.odb.store(IStream(Commit.type, streamlen, stream))
		assert istream.hexsha == cm.hexsha
		
		nc = Commit(rwrepo, Commit.NULL_BIN_SHA, cm.tree,
						cm.author, cm.authored_date, cm.author_tz_offset, 
						cm.committer, cm.committed_date, cm.committer_tz_offset, 
						cm.message, cm.parents, cm.encoding)
		
		assert nc.parents == cm.parents
		stream = StringIO()
		nc._serialize(stream)
		ns += 1
		streamlen = stream.tell()
		stream.seek(0)
		
		# reuse istream
		istream.size = streamlen
		istream.stream = stream
		istream.binsha = None
		nc.binsha = rwrepo.odb.store(istream).binsha
		
		# if it worked, we have exactly the same contents !
		assert nc.hexsha == cm.hexsha
	# END check commits
	elapsed = time.time() - st
	
	if print_performance_info:
		print >> sys.stderr, "Serialized %i and deserialized %i commits in %f s ( (%f, %f) commits / s" % (ns, nds, elapsed, ns/elapsed, nds/elapsed)
	# END handle performance info
	

class TestCommit(TestBase):

	def test_bake(self):

		commit = self.rorepo.commit('2454ae89983a4496a445ce347d7a41c0bb0ea7ae')
		# commits have no dict
		self.failUnlessRaises(AttributeError, setattr, commit, 'someattr', 1)
		commit.author # bake

		assert_equal("Sebastian Thiel", commit.author.name)
		assert_equal("byronimo@gmail.com", commit.author.email)
		assert commit.author == commit.committer
		assert isinstance(commit.authored_date, int) and isinstance(commit.committed_date, int)
		assert isinstance(commit.author_tz_offset, int) and isinstance(commit.committer_tz_offset, int)
		assert commit.message == "Added missing information to docstrings of commit and stats module\n"


	def test_stats(self):
		commit = self.rorepo.commit('33ebe7acec14b25c5f84f35a664803fcab2f7781')
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
		assert commit.author_tz_offset == 14400, commit.author_tz_offset
		assert commit.committer_tz_offset == 14400, commit.committer_tz_offset
		assert commit.message == "initial project\n"
		
	def test_unicode_actor(self):
		# assure we can parse unicode actors correctly
		name = "Üäöß ÄußÉ".decode("utf-8")
		assert len(name) == 9
		special = Actor._from_string(u"%s <something@this.com>" % name)
		assert special.name == name
		assert isinstance(special.name, unicode)
		
	def test_traversal(self):
		start = self.rorepo.commit("a4d06724202afccd2b5c54f81bcf2bf26dea7fff")
		first = self.rorepo.commit("33ebe7acec14b25c5f84f35a664803fcab2f7781")
		p0 = start.parents[0]
		p1 = start.parents[1]
		p00 = p0.parents[0]
		p10 = p1.parents[0]
		
		# basic branch first, depth first
		dfirst = start.traverse(branch_first=False)
		bfirst = start.traverse(branch_first=True)
		assert dfirst.next() == p0
		assert dfirst.next() == p00
		
		assert bfirst.next() == p0
		assert bfirst.next() == p1
		assert bfirst.next() == p00
		assert bfirst.next() == p10
		
		# at some point, both iterations should stop
		assert list(bfirst)[-1] == first
		stoptraverse = self.rorepo.commit("254d04aa3180eb8b8daf7b7ff25f010cd69b4e7d").traverse(as_edge=True)
		l = list(stoptraverse)
		assert len(l[0]) == 2
		
		# ignore self
		assert start.traverse(ignore_self=False).next() == start
		
		# depth 
		assert len(list(start.traverse(ignore_self=False, depth=0))) == 1
		
		# prune
		assert start.traverse(branch_first=1, prune=lambda i,d: i==p0).next() == p1
		
		# predicate
		assert start.traverse(branch_first=1, predicate=lambda i,d: i==p1).next() == p1
		
		# traversal should stop when the beginning is reached
		self.failUnlessRaises(StopIteration, first.traverse().next)
		
		# parents of the first commit should be empty ( as the only parent has a null 
		# sha )
		assert len(first.parents) == 0
		
	def test_iteration(self):
		# we can iterate commits
		all_commits = Commit.list_items(self.rorepo, self.rorepo.head)
		assert all_commits
		assert all_commits == list(self.rorepo.iter_commits())
		
		# this includes merge commits
		mcomit = self.rorepo.commit('d884adc80c80300b4cc05321494713904ef1df2d')
		assert mcomit in all_commits
		
		# we can limit the result to paths
		ltd_commits = list(self.rorepo.iter_commits(paths='CHANGES'))
		assert ltd_commits and len(ltd_commits) < len(all_commits)
		
		# show commits of multiple paths, resulting in a union of commits
		less_ltd_commits = list(Commit.iter_items(self.rorepo, 'master', paths=('CHANGES', 'AUTHORS')))
		assert len(ltd_commits) < len(less_ltd_commits)
		
	def test_iter_items(self):
		# pretty not allowed
		self.failUnlessRaises(ValueError, Commit.iter_items, self.rorepo, 'master', pretty="raw")
		
	def test_rev_list_bisect_all(self):
		"""
		'git rev-list --bisect-all' returns additional information
		in the commit header.  This test ensures that we properly parse it.
		"""
		revs = self.rorepo.git.rev_list('933d23bf95a5bd1624fbcdf328d904e1fa173474',
									  first_parent=True,
									  bisect_all=True)

		commits = Commit._iter_from_process_or_stream(self.rorepo, StringProcessAdapter(revs))
		expected_ids = (
			'7156cece3c49544abb6bf7a0c218eb36646fad6d',
			'1f66cfbbce58b4b552b041707a12d437cc5f400a',
			'33ebe7acec14b25c5f84f35a664803fcab2f7781',
			'933d23bf95a5bd1624fbcdf328d904e1fa173474'
		)
		for sha1, commit in zip(expected_ids, commits):
			assert_equal(sha1, commit.hexsha)

	def test_count(self):
		assert self.rorepo.tag('refs/tags/0.1.5').commit.count( ) == 143
		
	def test_list(self):
		assert isinstance(Commit.list_items(self.rorepo, '0.1.5', max_count=5)[hex_to_bin('5117c9c8a4d3af19a9958677e45cda9269de1541')], Commit)

	def test_str(self):
		commit = Commit(self.rorepo, Commit.NULL_BIN_SHA)
		assert_equal(Commit.NULL_HEX_SHA, str(commit))

	def test_repr(self):
		commit = Commit(self.rorepo, Commit.NULL_BIN_SHA)
		assert_equal('<git.Commit "%s">' % Commit.NULL_HEX_SHA, repr(commit))

	def test_equality(self):
		commit1 = Commit(self.rorepo, Commit.NULL_BIN_SHA)
		commit2 = Commit(self.rorepo, Commit.NULL_BIN_SHA)
		commit3 = Commit(self.rorepo, "\1"*20)
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
		
	def test_base(self):
		name_rev = self.rorepo.head.commit.name_rev
		assert isinstance(name_rev, basestring)
		
	@with_rw_repo('HEAD', bare=True)
	def test_serialization(self, rwrepo):
		# create all commits of our repo
		assert_commit_serialization(rwrepo, '0.1.6')
		
	def test_serialization_unicode_support(self):
		assert Commit.default_encoding.lower() == 'utf-8'
		
		# create a commit with unicode in the message, and the author's name
		# Verify its serialization and deserialization
		cmt = self.rorepo.commit('0.1.6')
		assert isinstance(cmt.message, unicode)		# it automatically decodes it as such
		assert isinstance(cmt.author.name, unicode)	# same here
		
		cmt.message = "üäêèß".decode("utf-8")
		assert len(cmt.message) == 5
		
		cmt.author.name = "äüß".decode("utf-8")
		assert len(cmt.author.name) == 3
		
		cstream = StringIO()
		cmt._serialize(cstream)
		cstream.seek(0)
		assert len(cstream.getvalue())
		
		ncmt = Commit(self.rorepo, cmt.binsha)
		ncmt._deserialize(cstream)
		
		assert cmt.author.name == ncmt.author.name
		assert cmt.message == ncmt.message
		# actually, it can't be printed in a shell as repr wants to have ascii only
		# it appears
		cmt.author.__repr__()
		
