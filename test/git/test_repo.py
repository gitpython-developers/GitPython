# test_repo.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os, sys
import time
from test.testlib import *
from git import *

class TestRepo(object):
    def setup(self):
        self.repo = Repo(GIT_REPO)
    
    @raises(InvalidGitRepositoryError)
    def test_new_should_raise_on_invalid_repo_location(self):
        if sys.platform == "win32":
            Repo("C:\\WINDOWS\\Temp")
        else:
            Repo("/tmp")

    @raises(NoSuchPathError)
    def test_new_should_raise_on_non_existant_path(self):
        Repo("repos/foobar")

    def test_description(self):
        txt = "Test repository"
        self.repo.description = txt
        assert_equal(self.repo.description, txt)

    def test_heads_should_return_array_of_head_objects(self):
        for head in self.repo.heads:
            assert_equal(Head, head.__class__)

    @patch_object(Git, '_call_process')
    def test_heads_should_populate_head_data(self, git):
        git.return_value = fixture('for_each_ref')

        head = self.repo.heads[0]
        assert_equal('master', head.name)
        assert_equal('634396b2f541a9f2d58b00be1a07f0c358b999b3', head.commit.id)

        assert_true(git.called)
        assert_equal(git.call_args, (('for_each_ref', 'refs/heads'), {'sort': 'committerdate', 'format': '%(refname)%00%(objectname)'}))

    @patch_object(Git, '_call_process')
    def test_commits(self, git):
        git.return_value = fixture('rev_list')

        commits = self.repo.commits('master', max_count=10)

        c = commits[0]
        assert_equal('4c8124ffcf4039d292442eeccabdeca5af5c5017', c.id)
        assert_equal(["634396b2f541a9f2d58b00be1a07f0c358b999b3"], [p.id for p in c.parents])
        assert_equal("672eca9b7f9e09c22dcb128c283e8c3c8d7697a4", c.tree.id)
        assert_equal("Tom Preston-Werner", c.author.name)
        assert_equal("tom@mojombo.com", c.author.email)
        assert_equal(time.gmtime(1191999972), c.authored_date)
        assert_equal("Tom Preston-Werner", c.committer.name)
        assert_equal("tom@mojombo.com", c.committer.email)
        assert_equal(time.gmtime(1191999972), c.committed_date)
        assert_equal("implement Grit#heads", c.message)

        c = commits[1]
        assert_equal([], c.parents)

        c = commits[2]
        assert_equal(["6e64c55896aabb9a7d8e9f8f296f426d21a78c2c", "7f874954efb9ba35210445be456c74e037ba6af2"], map(lambda p: p.id, c.parents))
        assert_equal("Merge branch 'site'", c.summary)

        assert_true(git.called)
        assert_equal(git.call_args, (('rev_list', 'master', '--', ''), {'skip': 0, 'pretty': 'raw', 'max_count': 10}))

    @patch_object(Git, '_call_process')
    def test_commit_count(self, git):
        git.return_value = fixture('rev_list_count')

        assert_equal(655, self.repo.commit_count('master'))

        assert_true(git.called)
        assert_equal(git.call_args, (('rev_list', 'master', '--', ''), {}))

    @patch_object(Git, '_call_process')
    def test_commit(self, git):
        git.return_value = fixture('rev_list_single')

        commit = self.repo.commit('4c8124ffcf4039d292442eeccabdeca5af5c5017')

        assert_equal("4c8124ffcf4039d292442eeccabdeca5af5c5017", commit.id)

        assert_true(git.called)
        assert_equal(git.call_args, (('rev_list', '4c8124ffcf4039d292442eeccabdeca5af5c5017', '--', ''), {'pretty': 'raw', 'max_count': 1}))

    @patch_object(Git, '_call_process')
    def test_tree(self, git):
        git.return_value = fixture('ls_tree_a')

        tree = self.repo.tree('master')

        assert_equal(4, len([c for c in tree.values() if isinstance(c, Blob)]))
        assert_equal(3, len([c for c in tree.values() if isinstance(c, Tree)]))

        assert_true(git.called)
        assert_equal(git.call_args, (('ls_tree', 'master'), {}))

    @patch_object(Git, '_call_process')
    def test_blob(self, git):
        git.return_value = fixture('cat_file_blob')

        blob = self.repo.blob("abc")
        assert_equal("Hello world", blob.data)

        assert_true(git.called)
        assert_equal(git.call_args, (('cat_file', 'abc'), {'p': True, 'with_raw_output': True}))

    @patch_object(Repo, '__init__')
    @patch_object(Git, '_call_process')
    def test_init_bare(self, git, repo):
        git.return_value = True
        repo.return_value = None

        Repo.init_bare("repos/foo/bar.git")

        assert_true(git.called)
        assert_equal(git.call_args, (('init', '--bare'), {}))
        assert_true(repo.called)
        assert_equal(repo.call_args, (('repos/foo/bar.git',), {}))

    @patch_object(Repo, '__init__')
    @patch_object(Git, '_call_process')
    def test_init_bare_with_options(self, git, repo):
        git.return_value = True
        repo.return_value = None

        Repo.init_bare("repos/foo/bar.git", **{'template': "/baz/sweet"})

        assert_true(git.called)
        assert_equal(git.call_args, (('init', '--bare'), {'template': '/baz/sweet'}))
        assert_true(repo.called)
        assert_equal(repo.call_args, (('repos/foo/bar.git',), {}))

    @patch_object(Repo, '__init__')
    @patch_object(Git, '_call_process')
    def test_fork_bare(self, git, repo):
        git.return_value = None
        repo.return_value = None

        self.repo.fork_bare("repos/foo/bar.git")

        assert_true(git.called)
        path = os.path.join(absolute_project_path(), '.git')
        assert_equal(git.call_args, (('clone', path, 'repos/foo/bar.git'), {'bare': True}))
        assert_true(repo.called)

    @patch_object(Repo, '__init__')
    @patch_object(Git, '_call_process')
    def test_fork_bare_with_options(self, git, repo):
        git.return_value = None
        repo.return_value = None

        self.repo.fork_bare("repos/foo/bar.git", **{'template': '/awesome'})

        assert_true(git.called)
        path = os.path.join(absolute_project_path(), '.git')
        assert_equal(git.call_args, (('clone', path, 'repos/foo/bar.git'),
                                      {'bare': True, 'template': '/awesome'}))
        assert_true(repo.called)

    @patch_object(Git, '_call_process')
    def test_diff(self, git):
        self.repo.diff('master^', 'master')

        assert_true(git.called)
        assert_equal(git.call_args, (('diff', 'master^', 'master', '--'), {}))

        self.repo.diff('master^', 'master', 'foo/bar')

        assert_true(git.called)
        assert_equal(git.call_args, (('diff', 'master^', 'master', '--', 'foo/bar'), {}))

        self.repo.diff('master^', 'master', 'foo/bar', 'foo/baz')

        assert_true(git.called)
        assert_equal(git.call_args, (('diff', 'master^', 'master', '--', 'foo/bar', 'foo/baz'), {}))

    @patch_object(Git, '_call_process')
    def test_diff_with_parents(self, git):
        git.return_value = fixture('diff_p')

        diffs = self.repo.commit_diff('master')
        assert_equal(15, len(diffs))
        assert_true(git.called)

    def test_archive_tar(self):
        self.repo.archive_tar()

    def test_archive_tar_gz(self):
        self.repo.archive_tar_gz()

    def test_disable_daemon_export(self):
    	prev_value = self.repo.daemon_export 
        self.repo.daemon_export = not prev_value
        assert_equal(self.repo.daemon_export, not prev_value)
        self.repo.daemon_export = prev_value
        assert_equal(self.repo.daemon_export, prev_value)
  
    def test_alternates(self):
        cur_alternates = self.repo.alternates
        # empty alternates
        self.repo.alternates = []
        assert self.repo.alternates == []
        alts = [ "other/location", "this/location" ]
        self.repo.alternates = alts
        assert alts == self.repo.alternates
        self.repo.alternates = cur_alternates

    def test_repr(self):
        path = os.path.join(os.path.abspath(GIT_REPO), '.git')
        assert_equal('<git.Repo "%s">' % path, repr(self.repo))

    @patch_object(Git, '_call_process')
    def test_log(self, git):
        git.return_value = fixture('rev_list')
        assert_equal('4c8124ffcf4039d292442eeccabdeca5af5c5017', self.repo.log()[0].id)
        assert_equal('ab25fd8483882c3bda8a458ad2965d2248654335', self.repo.log()[-1].id)
        assert_true(git.called)
        assert_equal(git.call_count, 2)
        assert_equal(git.call_args, (('log', 'master', '--'), {'pretty': 'raw'}))

    @patch_object(Git, '_call_process')
    def test_log_with_path_and_options(self, git):
        git.return_value = fixture('rev_list')
        self.repo.log('master', 'file.rb', **{'max_count': 1})
        assert_true(git.called)
        assert_equal(git.call_args, (('log', 'master', '--', 'file.rb'), {'pretty': 'raw', 'max_count': 1}))

    def test_is_dirty_with_bare_repository(self):
        self.repo.bare = True
        assert_false(self.repo.is_dirty)

    @patch_object(Git, '_call_process')
    def test_is_dirty_with_clean_working_dir(self, git):
        self.repo.bare = False
        git.return_value = ''
        assert_false(self.repo.is_dirty)
        assert_equal(git.call_args, (('diff', 'HEAD', '--'), {}))

    @patch_object(Git, '_call_process')
    def test_is_dirty_with_dirty_working_dir(self, git):
        self.repo.bare = False
        git.return_value = '''-aaa\n+bbb'''
        assert_true(self.repo.is_dirty)
        assert_equal(git.call_args, (('diff', 'HEAD', '--'), {}))

    @patch_object(Git, '_call_process')
    def test_active_branch(self, git):
        git.return_value = 'refs/heads/major-refactoring'
        assert_equal(self.repo.active_branch, 'major-refactoring')
        assert_equal(git.call_args, (('symbolic_ref', 'HEAD'), {}))
