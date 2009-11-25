# test_index.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *
import inspect
import os
import sys
import tempfile
import glob
import shutil
from stat import *

class TestTree(TestBase):
	
	def __init__(self, *args):
		super(TestTree, self).__init__(*args)
		self._reset_progress()
	
	def _assert_fprogress(self, entries):
		assert len(entries) == len(self._fprogress_map)
		for path, call_count in self._fprogress_map.iteritems():
			assert call_count == 2
		self._reset_progress()

	def _fprogress(self, path, done, item):
		self._fprogress_map.setdefault(path, 0)
		curval = self._fprogress_map[path]
		if curval == 0:
			assert not done
		if curval == 1:
			assert done
		self._fprogress_map[path] = curval + 1
		
	def _fprogress_add(self, path, done, item):
		"""Called as progress func - we keep track of the proper 
		call order"""
		assert item is not None
		self._fprogress(path, done, item)
		
	def _reset_progress(self):
		# maps paths to the count of calls
		self._fprogress_map = dict()
	
	def test_index_file_base(self):
		# read from file
		index = IndexFile(self.rorepo, fixture_path("index"))
		assert index.entries
		assert index.version > 0
		
		# test entry
		last_val = None
		entry = index.entries.itervalues().next()
		for attr in ("path","ctime","mtime","dev","inode","mode","uid",
								"gid","size","sha","stage"):
			val = getattr(entry, attr)
		# END for each method
		
		# test update
		entries = index.entries
		assert isinstance(index.update(), IndexFile)
		assert entries is not index.entries
		
		# test stage
		index_merge = IndexFile(self.rorepo, fixture_path("index_merge"))
		assert len(index_merge.entries) == 106
		assert len(list(e for e in index_merge.entries.itervalues() if e.stage != 0 ))
		
		# write the data - it must match the original
		tmpfile = tempfile.mktemp()
		index_merge.write(tmpfile)
		fp = open(tmpfile, 'rb')
		assert fp.read() == fixture("index_merge")
		fp.close()
		os.remove(tmpfile)
	
	def _cmp_tree_index(self, tree, index):
		# fail unless both objects contain the same paths and blobs
		if isinstance(tree, str):
			tree = self.rorepo.commit(tree).tree
		
		num_blobs = 0
		for blob in tree.traverse(predicate = lambda e: e.type == "blob"):
			assert (blob.path,0) in index.entries
			num_blobs += 1
		# END for each blob in tree
		assert num_blobs == len(index.entries)
	
	def test_index_file_from_tree(self):
		common_ancestor_sha = "5117c9c8a4d3af19a9958677e45cda9269de1541"
		cur_sha = "4b43ca7ff72d5f535134241e7c797ddc9c7a3573"
		other_sha = "39f85c4358b7346fee22169da9cad93901ea9eb9"
		
		# simple index from tree 
		base_index = IndexFile.from_tree(self.rorepo, common_ancestor_sha)
		assert base_index.entries
		self._cmp_tree_index(common_ancestor_sha, base_index)
		
		# merge two trees - its like a fast-forward
		two_way_index = IndexFile.from_tree(self.rorepo, common_ancestor_sha, cur_sha)
		assert two_way_index.entries
		self._cmp_tree_index(cur_sha, two_way_index)
		
		# merge three trees - here we have a merge conflict
		three_way_index = IndexFile.from_tree(self.rorepo, common_ancestor_sha, cur_sha, other_sha)
		assert len(list(e for e in three_way_index.entries.values() if e.stage != 0))
		
		
		# ITERATE BLOBS
		merge_required = lambda t: t[0] != 0
		merge_blobs = list(three_way_index.iter_blobs(merge_required))
		assert merge_blobs
		assert merge_blobs[0][0] in (1,2,3)
		assert isinstance(merge_blobs[0][1], Blob)
		
		
		# writing a tree should fail with an unmerged index
		self.failUnlessRaises(GitCommandError, three_way_index.write_tree)
		
		# removed unmerged entries
		unmerged_blob_map = three_way_index.unmerged_blobs()
		assert unmerged_blob_map
		
		# pick the first blob at the first stage we find and use it as resolved version
		three_way_index.resolve_blobs( l[0][1] for l in unmerged_blob_map.itervalues() )
		tree = three_way_index.write_tree()
		assert isinstance(tree, Tree)
		num_blobs = 0
		for blob in tree.traverse(predicate=lambda item: item.type == "blob"):
			assert (blob.path,0) in three_way_index.entries
			num_blobs += 1
		# END for each blob
		assert num_blobs == len(three_way_index.entries)
	
	@with_rw_repo('0.1.6')
	def test_index_merge_tree(self, rw_repo):
		# SINGLE TREE MERGE
		# current index is at the (virtual) cur_commit
		next_commit = "4c39f9da792792d4e73fc3a5effde66576ae128c"
		parent_commit = rw_repo.head.commit.parents[0]
		manifest_key = IndexFile.get_entries_key('MANIFEST.in', 0)
		manifest_entry = rw_repo.index.entries[manifest_key]
		rw_repo.index.merge_tree(next_commit)
		# only one change should be recorded
		assert manifest_entry.sha != rw_repo.index.entries[manifest_key].sha
		
		rw_repo.index.reset(rw_repo.head)
		assert rw_repo.index.entries[manifest_key].sha == manifest_entry.sha
		
		# FAKE MERGE
		#############
		# Add a change with a NULL sha that should conflict with next_commit. We 
		# pretend there was a change, but we do not even bother adding a proper 
		# sha for it ( which makes things faster of course )
		manifest_fake_entry = BaseIndexEntry((manifest_entry[0], Diff.null_hex_sha, 0, manifest_entry[3]))
		rw_repo.index.add([manifest_fake_entry])
		# add actually resolves the null-hex-sha for us as a feature, but we can 
		# edit the index manually
		assert rw_repo.index.entries[manifest_key].sha != Diff.null_hex_sha
		# must operate on the same index for this ! Its a bit problematic as 
		# it might confuse people
		index = rw_repo.index 
		index.entries[manifest_key] = IndexEntry.from_base(manifest_fake_entry)
		index.write()
		assert rw_repo.index.entries[manifest_key].sha == Diff.null_hex_sha
		
		# a three way merge would result in a conflict and fails as the command will 
		# not overwrite any entries in our index and hence leave them unmerged. This is 
		# mainly a protection feature as the current index is not yet in a tree
		self.failUnlessRaises(GitCommandError, index.merge_tree, next_commit, base=parent_commit)
		
		# the only way to get the merged entries is to safe the current index away into a tree, 
		# which is like a temporary commit for us. This fails as well as the NULL sha deos not
		# have a corresponding object
		self.failUnlessRaises(GitCommandError, index.write_tree)
		
		# if missing objects are okay, this would work though
		tree = index.write_tree(missing_ok = True)
		
		# now make a proper three way merge with unmerged entries
		unmerged_tree = IndexFile.from_tree(rw_repo, parent_commit, tree, next_commit)
		unmerged_blobs = unmerged_tree.unmerged_blobs()
		assert len(unmerged_blobs) == 1 and unmerged_blobs.keys()[0] == manifest_key[0]
		
	
	@with_rw_repo('0.1.6')
	def test_index_file_diffing(self, rw_repo):
		# default Index instance points to our index
		index = IndexFile(rw_repo)
		assert index.path is not None
		assert len(index.entries)
		
		# write the file back
		index.write()
		
		# could sha it, or check stats
		
		# test diff
		# resetting the head will leave the index in a different state, and the 
		# diff will yield a few changes
		cur_head_commit = rw_repo.head.reference.commit
		ref = rw_repo.head.reset('HEAD~6', index=True, working_tree=False)
		
		# diff against same index is 0
		diff = index.diff()
		assert len(diff) == 0
		
		# against HEAD as string, must be the same as it matches index
		diff = index.diff('HEAD')
		assert len(diff) == 0
		
		# against previous head, there must be a difference
		diff = index.diff(cur_head_commit)
		assert len(diff)
		
		# we reverse the result
		adiff = index.diff(str(cur_head_commit), R=True)
		odiff = index.diff(cur_head_commit, R=False)	# now its not reversed anymore
		assert adiff != odiff
		assert odiff == diff					# both unreversed diffs against HEAD
		
		# against working copy - its still at cur_commit
		wdiff = index.diff(None)
		assert wdiff != adiff
		assert wdiff != odiff
		
		# against something unusual
		self.failUnlessRaises(ValueError, index.diff, int)
		
		# adjust the index to match an old revision
		cur_branch = rw_repo.active_branch
		cur_commit = cur_branch.commit
		rev_head_parent = 'HEAD~1'
		assert index.reset(rev_head_parent) is index
		
		assert cur_branch == rw_repo.active_branch
		assert cur_commit == rw_repo.head.commit
		
		# there must be differences towards the working tree which is in the 'future'
		assert index.diff(None)
		
		# reset the working copy as well to current head,to pull 'back' as well
		new_data = "will be reverted"
		file_path = os.path.join(rw_repo.git.git_dir, "CHANGES")
		fp = open(file_path, "wb")
		fp.write(new_data)
		fp.close()
		index.reset(rev_head_parent, working_tree=True)
		assert not index.diff(None)
		assert cur_branch == rw_repo.active_branch
		assert cur_commit == rw_repo.head.commit
		fp = open(file_path,'rb')
		try:
			assert fp.read() != new_data
		finally:
			fp.close()
			
		# test full checkout
		test_file = os.path.join(rw_repo.git.git_dir, "CHANGES")
		open(test_file, 'ab').write("some data")
		rval = index.checkout(None, force=True, fprogress=self._fprogress)
		assert 'CHANGES' in list(rval)
		self._assert_fprogress([None])
		assert os.path.isfile(test_file)
		
		os.remove(test_file)
		rval = index.checkout(None, force=False, fprogress=self._fprogress)
		assert 'CHANGES' in list(rval)
		self._assert_fprogress([None])
		assert os.path.isfile(test_file)
		
		# individual file
		os.remove(test_file)
		rval = index.checkout(test_file, fprogress=self._fprogress)
		assert list(rval)[0] == 'CHANGES'
		self._assert_fprogress([test_file])
		assert os.path.exists(test_file)
		
		# checking out non-existing file throws
		self.failUnlessRaises(CheckoutError, index.checkout, "doesnt_exist_ever.txt.that")
		self.failUnlessRaises(CheckoutError, index.checkout, paths=["doesnt/exist"])
		
		# checkout file with modifications
		append_data = "hello"
		fp = open(test_file, "ab")
		fp.write(append_data)
		fp.close()
		try:
			index.checkout(test_file)
		except CheckoutError, e:
			assert len(e.failed_files) == 1 and e.failed_files[0] == os.path.basename(test_file)
			assert len(e.valid_files) == 0
			assert open(test_file).read().endswith(append_data)
		else:
			raise AssertionError("Exception CheckoutError not thrown")
	
		# if we force it it should work
		index.checkout(test_file, force=True)
		assert not open(test_file).read().endswith(append_data)
		
		# checkout directory
		shutil.rmtree(os.path.join(rw_repo.git.git_dir, "lib"))
		rval = index.checkout('lib')
		assert len(list(rval)) > 1
	
	def _count_existing(self, repo, files):
		"""
		Returns count of files that actually exist in the repository directory.
		"""
		existing = 0
		basedir = repo.git.git_dir
		for f in files:
			existing += os.path.isfile(os.path.join(basedir, f))
		# END for each deleted file
		return existing
	# END num existing helper
	
	@with_rw_repo('0.1.6')
	def test_index_mutation(self, rw_repo):
		index = rw_repo.index
		num_entries = len(index.entries)
		cur_head = rw_repo.head
		
		# remove all of the files, provide a wild mix of paths, BaseIndexEntries, 
		# IndexEntries
		def mixed_iterator():
			count = 0
			for entry in index.entries.itervalues():
				type_id = count % 4 
				if type_id == 0:	# path
					yield entry.path
				elif type_id == 1:	# blob
					yield Blob(rw_repo, entry.sha, entry.mode, entry.path)
				elif type_id == 2:	# BaseIndexEntry
					yield BaseIndexEntry(entry[:4])
				elif type_id == 3:	# IndexEntry
					yield entry
				else:
					raise AssertionError("Invalid Type")
				count += 1
			# END for each entry 
		# END mixed iterator
		deleted_files = index.remove(mixed_iterator(), working_tree=False)
		assert deleted_files
		assert self._count_existing(rw_repo, deleted_files) == len(deleted_files)
		assert len(index.entries) == 0
		
		# reset the index to undo our changes
		index.reset()
		assert len(index.entries) == num_entries
		
		# remove with working copy
		deleted_files = index.remove(mixed_iterator(), working_tree=True)
		assert deleted_files
		assert self._count_existing(rw_repo, deleted_files) == 0
		
		# reset everything
		index.reset(working_tree=True)
		assert self._count_existing(rw_repo, deleted_files) == len(deleted_files)
		
		# invalid type
		self.failUnlessRaises(TypeError, index.remove, [1])
		
		# absolute path
		deleted_files = index.remove([os.path.join(rw_repo.git.git_dir,"lib")], r=True)
		assert len(deleted_files) > 1
		self.failUnlessRaises(ValueError, index.remove, ["/doesnt/exists"])
		
		# TEST COMMITTING
		# commit changed index
		cur_commit = cur_head.commit
		commit_message = "commit default head"
		
		new_commit = index.commit(commit_message, head=False)
		assert new_commit.message == commit_message
		assert new_commit.parents[0] == cur_commit
		assert len(new_commit.parents) == 1
		assert cur_head.commit == cur_commit
		
		# same index, no parents
		commit_message = "index without parents"
		commit_no_parents = index.commit(commit_message, parent_commits=list(), head=True)
		assert commit_no_parents.message == commit_message
		assert len(commit_no_parents.parents) == 0
		assert cur_head.commit == commit_no_parents
		
		# same index, multiple parents
		commit_message = "Index with multiple parents\n    commit with another line"
		commit_multi_parent = index.commit(commit_message,parent_commits=(commit_no_parents, new_commit))
		assert commit_multi_parent.message == commit_message
		assert len(commit_multi_parent.parents) == 2
		assert commit_multi_parent.parents[0] == commit_no_parents
		assert commit_multi_parent.parents[1] == new_commit
		assert cur_head.commit == commit_multi_parent
		
		# re-add all files in lib
		# get the lib folder back on disk, but get an index without it
		index.reset(new_commit.parents[0], working_tree=True).reset(new_commit, working_tree=False)
		lib_file_path = "lib/git/__init__.py"
		assert (lib_file_path, 0) not in index.entries
		assert os.path.isfile(os.path.join(rw_repo.git.git_dir, lib_file_path))
		
		# directory
		entries = index.add(['lib'], fprogress=self._fprogress_add)
		self._assert_fprogress(entries)
		assert len(entries)>1
		
		# glob 
		entries = index.reset(new_commit).add(['lib/git/*.py'], fprogress=self._fprogress_add)
		self._assert_fprogress(entries)
		assert len(entries) == 14
		
		# same file 
		entries = index.reset(new_commit).add(['lib/git/head.py']*2, fprogress=self._fprogress_add)
		# would fail, test is too primitive to handle this case
		# self._assert_fprogress(entries)
		self._reset_progress()
		assert len(entries) == 2
		
		# missing path
		self.failUnlessRaises(GitCommandError, index.reset(new_commit).add, ['doesnt/exist/must/raise'])
		
		# blob from older revision overrides current index revision
		old_blob = new_commit.parents[0].tree.blobs[0]
		entries = index.reset(new_commit).add([old_blob], fprogress=self._fprogress_add)
		self._assert_fprogress(entries)
		assert index.entries[(old_blob.path,0)].sha == old_blob.sha and len(entries) == 1 
		
		# mode 0 not allowed
		null_sha = "0"*40
		self.failUnlessRaises(ValueError, index.reset(new_commit).add, [BaseIndexEntry((0, null_sha,0,"doesntmatter"))])
		
		# add new file
		new_file_relapath = "my_new_file"
		new_file_path = self._make_file(new_file_relapath, "hello world", rw_repo)
		entries = index.reset(new_commit).add([BaseIndexEntry((010644, null_sha, 0, new_file_relapath))], fprogress=self._fprogress_add)
		self._assert_fprogress(entries)
		assert len(entries) == 1 and entries[0].sha != null_sha
		
		# add symlink
		if sys.platform != "win32":
			link_file = os.path.join(rw_repo.git.git_dir, "my_real_symlink")
			os.symlink("/etc/that", link_file)
			entries = index.reset(new_commit).add([link_file], fprogress=self._fprogress_add)
			self._assert_fprogress(entries)
			assert len(entries) == 1 and S_ISLNK(entries[0].mode)
		# END real symlink test 
		
		# add fake symlink and assure it checks-our as symlink
		fake_symlink_relapath = "my_fake_symlink"
		link_target = "/etc/that"
		fake_symlink_path = self._make_file(fake_symlink_relapath, link_target, rw_repo)
		fake_entry = BaseIndexEntry((0120000, null_sha, 0, fake_symlink_relapath))
		entries = index.reset(new_commit).add([fake_entry], fprogress=self._fprogress_add)
		self._assert_fprogress(entries)
		assert entries[0].sha != null_sha
		assert len(entries) == 1 and S_ISLNK(entries[0].mode)
		
		# assure this also works with an alternate method
		full_index_entry = IndexEntry.from_base(BaseIndexEntry((0120000, entries[0].sha, 0, entries[0].path)))
		entry_key = index.get_entries_key(full_index_entry)
		index.reset(new_commit)
		
		assert entry_key not in index.entries
		index.entries[entry_key] = full_index_entry
		index.write()
		index.update()	# force reread of entries
		new_entry = index.entries[entry_key]
		assert S_ISLNK(new_entry.mode)
		
		# a tree created from this should contain the symlink
		tree = index.write_tree(True)
		assert fake_symlink_relapath in tree
		
		# checkout the fakelink, should be a link then
		assert not S_ISLNK(os.stat(fake_symlink_path)[ST_MODE])
		os.remove(fake_symlink_path)
		index.checkout(fake_symlink_path)
		
		# on windows we will never get symlinks
		if os.name == 'nt':
			# simlinks should contain the link as text ( which is what a 
			# symlink actually is )
			open(fake_symlink_path,'rb').read() == link_target 
		else:
			assert S_ISLNK(os.lstat(fake_symlink_path)[ST_MODE])
