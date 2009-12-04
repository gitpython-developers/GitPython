# test_refs.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from mock import *
from test.testlib import *
from git import *
import git.refs as refs
from git.objects.tag import TagObject
from itertools import chain
import os

class TestRefs(TestBase):

	def test_tag_base(self):
		tag_object_refs = list()
		for tag in self.rorepo.tags:
			assert "refs/tags" in tag.path
			assert tag.name
			assert isinstance( tag.commit, Commit )
			if tag.tag is not None:
				tag_object_refs.append( tag )
				tagobj = tag.tag
				assert isinstance( tagobj, TagObject ) 
				assert tagobj.tag == tag.name
				assert isinstance( tagobj.tagger, Actor )
				assert isinstance( tagobj.tagged_date, int )
				assert tagobj.message
			# END if we have a tag object
		# END for tag in repo-tags
		assert tag_object_refs
		assert isinstance(self.rorepo.tags['0.1.5'], TagReference)
		
	def test_tags(self):
		# tag refs can point to tag objects or to commits
		s = set()
		ref_count = 0
		for ref in chain(self.rorepo.tags, self.rorepo.heads):
			ref_count += 1
			assert isinstance(ref, refs.Reference)
			assert str(ref) == ref.name
			assert repr(ref)
			assert ref == ref
			assert not ref != ref
			s.add(ref)
		# END for each ref
		assert len(s) == ref_count
		assert len(s|s) == ref_count
		
	def test_heads(self):
		for head in self.rorepo.heads:
			assert head.name
			assert head.path
			assert "refs/heads" in head.path
			prev_object = head.object
			cur_object = head.object
			assert prev_object == cur_object		# represent the same git object
			assert prev_object is not cur_object	# but are different instances
		# END for each head
		
	def test_refs(self):
		types_found = set()
		for ref in self.rorepo.refs:
			types_found.add(type(ref))
		assert len(types_found) == 3 
		
	@with_rw_repo('0.1.6')
	def test_head_reset(self, rw_repo):
		cur_head = rw_repo.head
		new_head_commit = cur_head.ref.commit.parents[0]
		cur_head.reset(new_head_commit, index=True)	# index only
		assert cur_head.reference.commit == new_head_commit
		
		self.failUnlessRaises(ValueError, cur_head.reset, new_head_commit, index=False, working_tree=True)
		new_head_commit = new_head_commit.parents[0]
		cur_head.reset(new_head_commit, index=True, working_tree=True)	# index + wt
		assert cur_head.reference.commit == new_head_commit
		
		# paths
		cur_head.reset(new_head_commit, paths = "lib")
		
		
		# now that we have a write write repo, change the HEAD reference - its 
		# like git-reset --soft
		heads = rw_repo.heads
		assert heads
		for head in heads:
			cur_head.reference = head
			assert cur_head.reference == head
			assert isinstance(cur_head.reference, Head)
			assert cur_head.commit == head.commit
			assert not cur_head.is_detached
		# END for each head
		
		# detach
		active_head = heads[0]
		curhead_commit = active_head.commit
		cur_head.reference = curhead_commit
		assert cur_head.commit == curhead_commit
		assert cur_head.is_detached
		self.failUnlessRaises(TypeError, getattr, cur_head, "reference")
		
		# tags are references, hence we can point to them
		some_tag = rw_repo.tags[0]
		cur_head.reference = some_tag
		assert not cur_head.is_detached
		assert cur_head.commit == some_tag.commit
		assert isinstance(cur_head.reference, TagReference) 
		
		# put HEAD back to a real head, otherwise everything else fails
		cur_head.reference = active_head
		
		# type check
		self.failUnlessRaises(ValueError, setattr, cur_head, "reference", "that")
		
		# head handling 
		commit = 'HEAD'
		prev_head_commit = cur_head.commit
		for count, new_name in enumerate(("my_new_head", "feature/feature1")):
			actual_commit = commit+"^"*count
			new_head = Head.create(rw_repo, new_name, actual_commit)
			assert cur_head.commit == prev_head_commit
			assert isinstance(new_head, Head)
			# already exists
			self.failUnlessRaises(GitCommandError, Head.create, rw_repo, new_name)
			
			# force it
			new_head = Head.create(rw_repo, new_name, actual_commit, force=True)
			old_path = new_head.path
			old_name = new_head.name
			
			assert new_head.rename("hello").name == "hello"
			assert new_head.rename("hello/world").name == "hello/world"
			assert new_head.rename(old_name).name == old_name and new_head.path == old_path
			
			# rename with force
			tmp_head = Head.create(rw_repo, "tmphead")
			self.failUnlessRaises(GitCommandError, tmp_head.rename, new_head)
			tmp_head.rename(new_head, force=True)
			assert tmp_head == new_head and tmp_head.object == new_head.object
			
			Head.delete(rw_repo, tmp_head)
			heads = rw_repo.heads
			assert tmp_head not in heads and new_head not in heads
			# force on deletion testing would be missing here, code looks okay though ;)
		# END for each new head name
		self.failUnlessRaises(TypeError, RemoteReference.create, rw_repo, "some_name")  
		
		# tag ref
		tag_name = "1.0.2"
		light_tag = TagReference.create(rw_repo, tag_name)
		self.failUnlessRaises(GitCommandError, TagReference.create, rw_repo, tag_name)
		light_tag = TagReference.create(rw_repo, tag_name, "HEAD~1", force = True)
		assert isinstance(light_tag, TagReference)
		assert light_tag.name == tag_name
		assert light_tag.commit == cur_head.commit.parents[0]
		assert light_tag.tag is None
		
		# tag with tag object
		other_tag_name = "releases/1.0.2RC"
		msg = "my mighty tag\nsecond line"
		obj_tag = TagReference.create(rw_repo, other_tag_name, message=msg)
		assert isinstance(obj_tag, TagReference)
		assert obj_tag.name == other_tag_name
		assert obj_tag.commit == cur_head.commit
		assert obj_tag.tag is not None
		
		TagReference.delete(rw_repo, light_tag, obj_tag)
		tags = rw_repo.tags
		assert light_tag not in tags and obj_tag not in tags
		
		# remote deletion
		remote_refs_so_far = 0
		remotes = rw_repo.remotes 
		assert remotes
		for remote in remotes:
			refs = remote.refs
			RemoteReference.delete(rw_repo, *refs)
			remote_refs_so_far += len(refs)
		# END for each ref to delete
		assert remote_refs_so_far
		
		for remote in remotes:
			# remotes without references throw
			self.failUnlessRaises(AssertionError, getattr, remote, 'refs')
		# END for each remote
		
		# change where the active head points to
		if cur_head.is_detached:
			cur_head.reference = rw_repo.heads[0]
		
		head = cur_head.reference
		old_commit = head.commit
		head.commit = old_commit.parents[0]
		assert head.commit == old_commit.parents[0]
		assert head.commit == cur_head.commit
		head.commit = old_commit
		
		# setting a non-commit as commit fails, but succeeds as object
		head_tree = head.commit.tree
		self.failUnlessRaises(ValueError, setattr, head, 'commit', head_tree)
		assert head.commit == old_commit		# and the ref did not change
		self.failUnlessRaises(GitCommandError, setattr, head, 'object', head_tree)
		
		# set the commit directly using the head. This would never detach the head
		assert not cur_head.is_detached
		head.object = old_commit
		cur_head.reference = head.commit
		assert cur_head.is_detached
		parent_commit = head.commit.parents[0]
		assert cur_head.is_detached
		cur_head.commit = parent_commit
		assert cur_head.is_detached and cur_head.commit == parent_commit
		
		cur_head.reference = head
		assert not cur_head.is_detached
		cur_head.commit = parent_commit
		assert not cur_head.is_detached
		assert head.commit == parent_commit
		
		# test checkout
		active_branch = rw_repo.active_branch
		for head in rw_repo.heads:
			checked_out_head = head.checkout()
			assert checked_out_head == head
		# END for each head to checkout
		
		# checkout with branch creation
		new_head = active_branch.checkout(b="new_head")
		assert active_branch != rw_repo.active_branch
		assert new_head == rw_repo.active_branch
		
		# checkout  with force as we have a changed a file
		# clear file
		open(new_head.commit.tree.blobs[-1].abspath,'w').close()
		assert len(new_head.commit.diff(None))
		
		# create a new branch that is likely to touch the file we changed
		far_away_head = rw_repo.create_head("far_head",'HEAD~100')
		self.failUnlessRaises(GitCommandError, far_away_head.checkout)
		assert active_branch == active_branch.checkout(force=True)
		assert rw_repo.head.reference != far_away_head
		
		# test reference creation
		partial_ref = 'sub/ref'
		full_ref = 'refs/%s' % partial_ref
		ref = Reference.create(rw_repo, partial_ref)
		assert ref.path == full_ref
		assert ref.object == rw_repo.head.commit
		
		self.failUnlessRaises(OSError, Reference.create, rw_repo, full_ref, 'HEAD~20')
		# it works if it is at the same spot though and points to the same reference
		assert Reference.create(rw_repo, full_ref, 'HEAD').path == full_ref
		Reference.delete(rw_repo, full_ref)
		
		# recreate the reference using a full_ref
		ref = Reference.create(rw_repo, full_ref)
		assert ref.path == full_ref
		assert ref.object == rw_repo.head.commit
		
		# recreate using force
		ref = Reference.create(rw_repo, partial_ref, 'HEAD~1', force=True)
		assert ref.path == full_ref
		assert ref.object == rw_repo.head.commit.parents[0]
		
		# rename it
		orig_obj = ref.object
		for name in ('refs/absname', 'rela_name', 'feature/rela_name'):
			ref_new_name = ref.rename(name)
			assert isinstance(ref_new_name, Reference)
			assert name in ref_new_name.path
			assert ref_new_name.object == orig_obj
			assert ref_new_name == ref
		# END for each name type
		# exists, fail unless we force
		ex_ref_path = far_away_head.path
		self.failUnlessRaises(OSError, ref.rename, ex_ref_path)
		# if it points to the same commit it works
		far_away_head.commit = ref.commit
		ref.rename(ex_ref_path)
		assert ref.path == ex_ref_path and ref.object == orig_obj
		assert ref.rename(ref.path).path == ex_ref_path	# rename to same name
		
		# create symbolic refs
		symref_path = "symrefs/sym"
		symref = SymbolicReference.create(rw_repo, symref_path, cur_head.reference)
		assert symref.path == symref_path
		assert symref.reference == cur_head.reference
		
		self.failUnlessRaises(OSError, SymbolicReference.create, rw_repo, symref_path, cur_head.reference.commit)
		# it works if the new ref points to the same reference 
		SymbolicReference.create(rw_repo, symref.path, symref.reference).path == symref.path
		SymbolicReference.delete(rw_repo, symref)
		# would raise if the symref wouldn't have been deletedpbl
		symref = SymbolicReference.create(rw_repo, symref_path, cur_head.reference)
		
		# test symbolic references which are not at default locations like HEAD
		# or FETCH_HEAD - they may also be at spots in refs of course
		symbol_ref_path = "refs/symbol_ref"
		symref = SymbolicReference(rw_repo, symbol_ref_path)
		assert symref.path == symbol_ref_path
		symbol_ref_abspath = os.path.join(rw_repo.git_dir, symref.path)
		
		# set it
		symref.reference = new_head
		assert symref.reference == new_head
		assert os.path.isfile(symbol_ref_abspath)
		assert symref.commit == new_head.commit
		
		for name in ('absname','folder/rela_name'):
			symref_new_name = symref.rename(name)
			assert isinstance(symref_new_name, SymbolicReference)
			assert name in symref_new_name.path
			assert symref_new_name.reference == new_head
			assert symref_new_name == symref
			assert not symref.is_detached
		# END for each ref
		
		# test ref listing - assure we have packed refs
		rw_repo.git.pack_refs(all=True, prune=True)
		heads = rw_repo.heads
		assert heads
		assert new_head in heads
		assert active_branch in heads
		assert rw_repo.tags
		
