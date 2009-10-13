# test_tree.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *

class TestTree(TestCase):
	
	def setUp(self):
		self.repo = Repo(GIT_REPO)

	@patch_object(Git, '_call_process')
	def test_contents_should_cache(self, git):
		git.return_value = fixture('ls_tree_a') + fixture('ls_tree_b')
	
		tree = self.repo.tree(Head(self.repo,'master'))

		child = tree['grit']
		len(child)
		len(child)
		
		assert_true(git.called)
		assert_equal(2, git.call_count)
		assert_equal(git.call_args, (('ls_tree', '34868e6e7384cb5ee51c543a8187fdff2675b5a7'), {}))
	
	@raises(TypeError)
	def test__from_string_invalid_type_should_raise(self):
		Tree._from_string(None, "040000 bogus 650fa3f0c17f1edb4ae53d8dcca4ac59d86e6c44	test")

	@patch_object(Blob, 'size')
	@patch_object(Git, '_call_process')
	def test_slash(self, git, blob):
		git.return_value = fixture('ls_tree_a')
		blob.return_value = 1
		
		tree = self.repo.tree(Head(self.repo,'master'))
		
		assert_equal('aa06ba24b4e3f463b3c4a85469d0fb9e5b421cf8', (tree/'lib').id)
		assert_equal('8b1e02c0fb554eed2ce2ef737a68bb369d7527df', (tree/'README.txt').id)
		
		assert_true(git.called)
		
	def test_traverse(self):
		root = self.repo.tree()
		num_recursive = 0
		all_items = list()
		for obj in root.traverse():
			if "/" in obj.path:
				num_recursive += 1
				
			assert isinstance(obj, (Blob, Tree))
			all_items.append(obj)
		# END for each object
		# limit recursion level to 0 - should be same as default iteration
		assert all_items
		assert 'CHANGES' in root
		assert len(list(root)) == len(list(root.traverse(max_depth=0)))
		
		# only choose trees
		trees_only = lambda i: i.type == "tree"
		trees = list(root.traverse(predicate = trees_only))
		assert len(trees) == len(list( i for i in root.traverse() if trees_only(i) ))
		
		# trees and blobs
		assert len(set(trees)|set(root.trees)) == len(trees)
		assert len(set(b for b in root if isinstance(b, Blob)) | set(root.blobs)) == len( root.blobs )
  
	@patch_object(Blob, 'size')
	@patch_object(Git, '_call_process')
	def test_slash_with_zero_length_file(self, git, blob):
		git.return_value = fixture('ls_tree_a')
		blob.return_value = 0
		
		tree = self.repo.tree(Head(self.repo,'master'))
		
		assert_not_none(tree/'README.txt')
		assert_equal('8b1e02c0fb554eed2ce2ef737a68bb369d7527df', (tree/'README.txt').id)
		
		assert_true(git.called)
  
	@patch_object(Git, '_call_process')
	def test_slash_with_commits(self, git):
		git.return_value = fixture('ls_tree_commit')

		tree = self.repo.tree(Head(self.repo,'master'))
	
		self.failUnlessRaises(KeyError, tree.__div__, 'bar')
		assert_equal('2afb47bcedf21663580d5e6d2f406f08f3f65f19', (tree/'foo').id)
		assert_equal('f623ee576a09ca491c4a27e48c0dfe04be5f4a2e', (tree/'baz').id)

		assert_true(git.called)

	@patch_object(Blob, 'size')
	@patch_object(Git, '_call_process')
	def test_dict(self, git, blob):
		git.return_value = fixture('ls_tree_a')
		blob.return_value = 1

		tree = self.repo.tree(Head(self.repo,'master'))

		assert_equal('aa06ba24b4e3f463b3c4a85469d0fb9e5b421cf8', tree['lib'].id)
		assert_equal('8b1e02c0fb554eed2ce2ef737a68bb369d7527df', tree['README.txt'].id)

		assert_true(git.called)

	@patch_object(Blob, 'size')
	@patch_object(Git, '_call_process')
	def test_dict_with_zero_length_file(self, git, blob):
		git.return_value = fixture('ls_tree_a')
		blob.return_value = 0

		tree = self.repo.tree(Head(self.repo,'master'))

		assert_not_none(tree['README.txt'])
		assert_equal('8b1e02c0fb554eed2ce2ef737a68bb369d7527df', tree['README.txt'].id)

		assert_true(git.called)

	@patch_object(Git, '_call_process')
	def test_dict_with_commits(self, git):
		git.return_value = fixture('ls_tree_commit')

		tree = self.repo.tree(Head(self.repo,'master'))

		self.failUnlessRaises(KeyError, tree.__getitem__, 'bar')
		assert_equal('2afb47bcedf21663580d5e6d2f406f08f3f65f19', tree['foo'].id)
		assert_equal('f623ee576a09ca491c4a27e48c0dfe04be5f4a2e', tree['baz'].id)

		assert_true(git.called)

	@patch_object(Git, '_call_process')
	@raises(KeyError)
	def test_dict_with_non_existant_file(self, git):
		git.return_value = fixture('ls_tree_commit')

		tree = self.repo.tree(Head(self.repo,'master'))
		tree['bar']

	def test_repr(self):
		tree = Tree(self.repo, id='abc')
		assert_equal('<git.Tree "abc">', repr(tree))
