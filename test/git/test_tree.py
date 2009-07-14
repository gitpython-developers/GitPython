# test_tree.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *

class TestTree(object):
    def setup(self):
        self.repo = Repo(GIT_REPO)

    @patch_object(Git, '_call_process')
    def test_contents_should_cache(self, git):
        git.return_value = fixture('ls_tree_a') + fixture('ls_tree_b')
    
        tree = self.repo.tree('master')

        child = tree['grit']
        child.items()
        child.items()
        
        assert_true(git.called)
        assert_equal(2, git.call_count)
        assert_equal(git.call_args, (('ls_tree', '34868e6e7384cb5ee51c543a8187fdff2675b5a7'), {}))
  
    def test_content_from_string_tree_should_return_tree(self):
        text = fixture('ls_tree_a').splitlines()[-1]
        tree = Tree.content_from_string(None, text)

        assert_equal(Tree, tree.__class__)
        assert_equal("650fa3f0c17f1edb4ae53d8dcca4ac59d86e6c44", tree.id)
        assert_equal("040000", tree.mode)
        assert_equal("test", tree.name)
  
    def test_content_from_string_tree_should_return_blob(self):
        text = fixture('ls_tree_b').split("\n")[0]
        
        tree = Tree.content_from_string(None, text)

        assert_equal(Blob, tree.__class__)
        assert_equal("aa94e396335d2957ca92606f909e53e7beaf3fbb", tree.id)
        assert_equal("100644", tree.mode)
        assert_equal("grit.rb", tree.name)
  
    def test_content_from_string_tree_should_return_commit(self):
        text = fixture('ls_tree_commit').split("\n")[1]
    
        tree = Tree.content_from_string(None, text)
        assert_none(tree)
    
    @raises(TypeError)
    def test_content_from_string_invalid_type_should_raise(self):
        Tree.content_from_string(None, "040000 bogus 650fa3f0c17f1edb4ae53d8dcca4ac59d86e6c44	test")

    @patch_object(Blob, 'size')
    @patch_object(Git, '_call_process')
    def test_slash(self, git, blob):
        git.return_value = fixture('ls_tree_a')
        blob.return_value = 1
        
        tree = self.repo.tree('master')
        
        assert_equal('aa06ba24b4e3f463b3c4a85469d0fb9e5b421cf8', (tree/'lib').id)
        assert_equal('8b1e02c0fb554eed2ce2ef737a68bb369d7527df', (tree/'README.txt').id)
        
        assert_true(git.called)
        assert_equal(git.call_args, (('ls_tree', 'master'), {}))
  
    @patch_object(Blob, 'size')
    @patch_object(Git, '_call_process')
    def test_slash_with_zero_length_file(self, git, blob):
        git.return_value = fixture('ls_tree_a')
        blob.return_value = 0
        
        tree = self.repo.tree('master')
        
        assert_not_none(tree/'README.txt')
        assert_equal('8b1e02c0fb554eed2ce2ef737a68bb369d7527df', (tree/'README.txt').id)
        
        assert_true(git.called)
        assert_equal(git.call_args, (('ls_tree', 'master'), {}))
  
    @patch_object(Git, '_call_process')
    def test_slash_with_commits(self, git):
        git.return_value = fixture('ls_tree_commit')

        tree = self.repo.tree('master')
    
        assert_none(tree/'bar')
        assert_equal('2afb47bcedf21663580d5e6d2f406f08f3f65f19', (tree/'foo').id)
        assert_equal('f623ee576a09ca491c4a27e48c0dfe04be5f4a2e', (tree/'baz').id)

        assert_true(git.called)
        assert_equal(git.call_args, (('ls_tree', 'master'), {}))

    @patch_object(Blob, 'size')
    @patch_object(Git, '_call_process')
    def test_dict(self, git, blob):
        git.return_value = fixture('ls_tree_a')
        blob.return_value = 1

        tree = self.repo.tree('master')

        assert_equal('aa06ba24b4e3f463b3c4a85469d0fb9e5b421cf8', tree['lib'].id)
        assert_equal('8b1e02c0fb554eed2ce2ef737a68bb369d7527df', tree['README.txt'].id)

        assert_true(git.called)
        assert_equal(git.call_args, (('ls_tree', 'master'), {}))

    @patch_object(Blob, 'size')
    @patch_object(Git, '_call_process')
    def test_dict_with_zero_length_file(self, git, blob):
        git.return_value = fixture('ls_tree_a')
        blob.return_value = 0

        tree = self.repo.tree('master')

        assert_not_none(tree['README.txt'])
        assert_equal('8b1e02c0fb554eed2ce2ef737a68bb369d7527df', tree['README.txt'].id)

        assert_true(git.called)
        assert_equal(git.call_args, (('ls_tree', 'master'), {}))

    @patch_object(Git, '_call_process')
    def test_dict_with_commits(self, git):
        git.return_value = fixture('ls_tree_commit')

        tree = self.repo.tree('master')

        assert_none(tree.get('bar'))
        assert_equal('2afb47bcedf21663580d5e6d2f406f08f3f65f19', tree['foo'].id)
        assert_equal('f623ee576a09ca491c4a27e48c0dfe04be5f4a2e', tree['baz'].id)

        assert_true(git.called)
        assert_equal(git.call_args, (('ls_tree', 'master'), {}))

    @patch_object(Git, '_call_process')
    @raises(KeyError)
    def test_dict_with_non_existant_file(self, git):
        git.return_value = fixture('ls_tree_commit')

        tree = self.repo.tree('master')
        tree['bar']

    def test_repr(self):
        tree = Tree(self.repo, id='abc')
        assert_equal('<git.Tree "abc">', repr(tree))
