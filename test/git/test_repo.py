import os
import time
from test.testlib import *
from git_python import *

class TestRepo(object):
    def setup(self):
        self.repo = Repo(GIT_REPO)
    
    @raises(InvalidGitRepositoryError)
    def test_new_should_raise_on_invalid_repo_location(self):
        Repo("/tmp")

    @raises(NoSuchPathError)
    def test_new_should_raise_on_non_existant_path(self):
        Repo("/foobar")

    def test_description(self):
        assert_equal("Unnamed repository; edit this file to name it for gitweb.", self.repo.description)

    def test_heads_should_return_array_of_head_objects(self):
        for head in self.repo.heads:
            assert_equal(Head, head.__class__)

    @patch(Git, 'method_missing')
    def test_heads_should_populate_head_data(self, git):
        # Git.any_instance.expects(:for_each_ref).returns(fixture('for_each_ref'))
        git.return_value = fixture('for_each_ref')
        
        head = self.repo.heads[0]
        assert_equal('master', head.name)
        assert_equal('634396b2f541a9f2d58b00be1a07f0c358b999b3', head.commit.id)
        
        assert_true(git.called)
        assert_equal(git.call_args, (('for_each_ref', 'refs/heads'), {'sort': 'committerdate', 'format': '%(refname)%00%(objectname)'}))

    @patch(Git, 'method_missing')  
    def test_commits(self, git):
        # Git.any_instance.expects(:rev_list).returns(fixture('rev_list'))
        git.return_value = fixture('rev_list')
        
        commits = self.repo.commits('master', 10)
    
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
        assert_equal("Merge branch 'site'", c.message)

        assert_true(git.called)
        assert_equal(git.call_args, (('rev_list', 'master'), {'skip': 0, 'pretty': 'raw', 'max_count': 10}))

    @patch(Git, 'method_missing')
    def test_commit_count(self, git):
        # Git.any_instance.expects(:rev_list).with({}, 'master').returns(fixture('rev_list_count'))
        git.return_value = fixture('rev_list_count')
        
        assert_equal(655, self.repo.commit_count('master'))
        
        assert_true(git.called)
        assert_equal(git.call_args, (('rev_list', 'master'), {}))
  
    def test_commit(self):
        commit = self.repo.commit('634396b2f541a9f2d58b00be1a07f0c358b999b3')
        
        assert_equal("634396b2f541a9f2d58b00be1a07f0c358b999b3", commit.id)
  
    @patch(Git, 'method_missing')
    def test_tree(self, git):
        # Git.any_instance.expects(:ls_tree).returns(fixture('ls_tree_a'))
        git.return_value = fixture('ls_tree_a')
        
        tree = self.repo.tree('master')
        
        assert_equal(4, len([c for c in tree.contents if isinstance(c, Blob)]))
        assert_equal(3, len([c for c in tree.contents if isinstance(c, Tree)]))
        
        assert_true(git.called)
        assert_equal(git.call_args, (('ls_tree', 'master'), {}))

    @patch(Git, 'method_missing')
    def test_blob(self, git):
        # Git.any_instance.expects(:cat_file).returns(fixture('cat_file_blob'))
        git.return_value = fixture('cat_file_blob')
        
        blob = self.repo.blob("abc")
        assert_equal("Hello world", blob.data)
        
        assert_true(git.called)
        assert_equal(git.call_args, (('cat_file', 'abc'), {'p': True}))

    @patch(Repo, '__init__')
    @patch(Git, 'method_missing')
    def test_init_bare(self, repo, git):
        # Git.any_instance.expects(:init).returns(true)
        # Repo.expects(:new).with("/foo/bar.git")
        git.return_value = True
        
        Repo.init_bare("/foo/bar.git")
        
        assert_true(git.called)
        assert_equal(git.call_args, (('init',), {}))
        assert_true(repo.called)
        assert_equal(repo.call_args, (('/foo/bar.git',), {}))

    @patch(Repo, '__init__')
    @patch(Git, 'method_missing')
    def test_init_bare_with_options(self, repo, git):
        # Git.any_instance.expects(:init).with(
        # :template => "/baz/sweet").returns(true)
        # Repo.expects(:new).with("/foo/bar.git")
        git.return_value = True
        
        Repo.init_bare("/foo/bar.git", **{'template': "/baz/sweet"})

        assert_true(git.called)
        assert_equal(git.call_args, (('init',), {'template': '/baz/sweet'}))
        assert_true(repo.called)
        assert_equal(repo.call_args, (('/foo/bar.git',), {}))

    @patch(Repo, '__init__')
    @patch(Git, 'method_missing')
    def test_fork_bare(self, repo, git):
        # Git.any_instance.expects(:clone).with(
        #           {:bare => true, :shared => false}, 
        #           "#{absolute_project_path}/.git",
        #           "/foo/bar.git").returns(nil)
        # Repo.expects(:new)
        git.return_value = None
        
        self.repo.fork_bare("/foo/bar.git")
        
        assert_true(git.called)
        assert_equal(git.call_args, (('clone', '%s/.git' % absolute_project_path(), '/foo/bar.git'), {'bare': True, 'shared': False}))
        assert_true(repo.called)

    @patch(Repo, '__init__')
    @patch(Git, 'method_missing')
    def test_fork_bare_with_options(self, repo, git):
        # Git.any_instance.expects(:clone).with(
        #       {:bare => true, :shared => false, :template => '/awesome'}, 
        #       "#{absolute_project_path}/.git",
        #       "/foo/bar.git").returns(nil)
        #     Repo.expects(:new)
        git.return_value = None
        
        self.repo.fork_bare("/foo/bar.git", **{'template': '/awesome'})
        
        assert_true(git.called)
        assert_equal(git.call_args, (('clone', '%s/.git' % absolute_project_path(), '/foo/bar.git'), 
                                      {'bare': True, 'shared': False, 'template': '/awesome'}))
        assert_true(repo.called)

    @patch(Git, 'method_missing')
    def test_diff(self, git):
        # Git.any_instance.expects(:diff).with({}, 'master^', 'master', '--')
        self.repo.diff('master^', 'master')
        
        assert_true(git.called)
        assert_equal(git.call_args, (('diff', 'master^', 'master', '--'), {}))

        # Git.any_instance.expects(:diff).with({}, 'master^', 'master', '--', 'foo/bar')
        self.repo.diff('master^', 'master', 'foo/bar')

        assert_true(git.called)
        assert_equal(git.call_args, (('diff', 'master^', 'master', '--', 'foo/bar'), {}))
        
        # Git.any_instance.expects(:diff).with({}, 'master^', 'master', '--', 'foo/bar', 'foo/baz')
        self.repo.diff('master^', 'master', 'foo/bar', 'foo/baz')
        
        assert_true(git.called)
        assert_equal(git.call_args, (('diff', 'master^', 'master', '--', 'foo/bar', 'foo/baz'), {}))

    @patch(Git, 'method_missing')
    def test_diff(self, git):
        # Git.any_instance.expects(:diff).returns(fixture('diff_p'))
        git.return_value = fixture('diff_p')
        
        diffs = self.repo.commit_diff('master')
        assert_equal(15, len(diffs))
        assert_true(git.called)

    def test_archive_tar(self):
        self.repo.archive_tar
  
    def test_archive_tar_gz(self):
        self.repo.archive_tar_gz

    @patch('git_python.utils', 'touch')
    def test_enable_daemon_serve(self, touch):
        # FileUtils.expects(:touch).with(File.join(self.repo.path, '.git', 'git-daemon-export-ok'))
        self.repo.enable_daemon_serve

    def test_disable_daemon_serve(self):
        # FileUtils.expects(:rm_f).with(File.join(self.repo.path, '.git', 'git-daemon-export-ok'))
        self.repo.disable_daemon_serve  
  
    # @patch(os.path, 'exists')
    #     @patch('__builtin__', 'open')
    #     def test_alternates_with_two_alternates(self, exists, read):
    #         # File.expects(:exist?).with("#{absolute_project_path}/.git/objects/info/alternates").returns(true)
    #         # File.expects(:read).returns("/path/to/repo1/.git/objects\n/path/to/repo2.git/objects\n")        
    #         exists.return_value = True
    #         read.return_value = ("/path/to/repo1/.git/objects\n/path/to/repo2.git/objects\n")
    #         
    #         assert_equal(["/path/to/repo1/.git/objects", "/path/to/repo2.git/objects"], self.repo.alternates)
    #         
    #         assert_true(exists.called)
    #         assert_true(read.called)
    # 
    #     @patch(os.path, 'exists')
    #     def test_alternates_no_file(self, os):
    #         os.return_value = False
    #         # File.expects(:exist?).returns(false)
    #         assert_equal([], self.repo.alternates)
    #         
    #         assert_true(os.called)
    #         
    #     @patch(os.path, 'exists')
    #     def test_alternates_setter_ok(self, os):
    #         os.return_value = True
    #         alts = ['/path/to/repo.git/objects', '/path/to/repo2.git/objects']
    #         
    #         # File.any_instance.expects(:write).with(alts.join("\n"))
    #         
    #         self.repo.alternates = alts
    #         
    #         assert_true(os.called)
    #         # assert_equal(os.call_args, ((alts,), {}))
    #         # for alt in alts:
    #             
    #     @patch(os.path, 'exists')
    #     @raises(NoSuchPathError)
    #     def test_alternates_setter_bad(self, os):
    #         os.return_value = False
    #         
    #         alts = ['/path/to/repo.git/objects']
    #         # File.any_instance.expects(:write).never
    #         self.repo.alternates = alts
    #         
    #         for alt in alts:
    #             assert_true(os.called)
    #             assert_equal(os.call_args, (alt, {}))
    #     
    #     @patch(os, 'remove')
    #     def test_alternates_setter_empty(self, os):
    #         self.repo.alternates = []
    #         assert_true(os.called)

    def test_repr(self):
        assert_equal('<GitPython.Repo "%s/.git">' % os.path.abspath(GIT_REPO), repr(self.repo))

    @patch(Git, 'method_missing')
    def test_log(self, git):
        git.return_value = fixture('rev_list')
        assert_equal('4c8124ffcf4039d292442eeccabdeca5af5c5017', self.repo.log()[0].id)
        assert_equal('ab25fd8483882c3bda8a458ad2965d2248654335', self.repo.log()[-1].id)
        assert_true(git.called)
        assert_equal(git.call_count, 2)
        assert_equal(git.call_args, (('log', 'master'), {'pretty': 'raw'}))

    @patch(Git, 'method_missing')
    def test_log_with_path_and_options(self, git):
        git.return_value = fixture('rev_list')
        self.repo.log('master', 'file.rb', **{'max_count': 1})
        assert_true(git.called)
        assert_equal(git.call_args, (('log', 'master', '--', 'file.rb'), {'pretty': 'raw', 'max_count': 1}))

    @patch(Git, 'method_missing')
    @patch(Git, 'method_missing')
    def test_commit_deltas_from_nothing_new(self, gitb, gita):
        gitb.return_value = fixture("rev_list_delta_b")
        gita.return_value = fixture("rev_list_delta_a")
        other_repo = Repo(GIT_REPO)
        # self.repo.git.expects(:rev_list).with({}, "master").returns(fixture("rev_list_delta_b"))
        # other_repo.git.expects(:rev_list).with({}, "master").returns(fixture("rev_list_delta_a"))
        
        delta_commits = self.repo.commit_deltas_from(other_repo)
        assert_equal(0, len(delta_commits))
        assert_true(gitb.called)
        assert_equal(gitb.call_args, (('rev_list', 'master'), {}))
        assert_true(gita.called)
        assert_equal(gita.call_args, (('rev_list', 'master'), {}))
  
    def test_commit_deltas_from_when_other_has_new(self):
        other_repo = Repo(GIT_REPO)
        # self.repo.git.expects(:rev_list).with({}, "master").returns(fixture("rev_list_delta_a"))
        # other_repo.git.expects(:rev_list).with({}, "master").returns(fixture("rev_list_delta_b"))
        # for ref in ['4c8124ffcf4039d292442eeccabdeca5af5c5017',
        #             '634396b2f541a9f2d58b00be1a07f0c358b999b3',
        #             'ab25fd8483882c3bda8a458ad2965d2248654335']:
        #     Commit.expects(:find_all).with(other_repo, ref, :max_count => 1).returns([stub()])
        delta_commits = self.repo.commit_deltas_from(other_repo)
        assert_equal(3, len(delta_commits))
