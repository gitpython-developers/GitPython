from mock import *
from gitalicious.test.asserts import *
from gitalicious.lib import *
from gitalicious.test.helper import *

class TestCommit(object):
    def setup(self):
        self.repo = Repo(GIT_REPO)

    @patch(Git, 'method_missing')
    def test_bake(self, git):
        git.return_value = fixture('rev_list_single')
        
        commit = Commit(self.repo, **{'id': '4c8124ffcf4039d292442eeccabdeca5af5c5017'})
        commit.author # bake
        
        assert_equal("Tom Preston-Werner", commit.author.name)
        assert_equal("tom@mojombo.com", commit.author.email)
 
        assert_true(git.called)
        assert_equal(git.call_args, (('rev_list', '4c8124ffcf4039d292442eeccabdeca5af5c5017'), {'pretty': 'raw', 'max_count': 1}))

    @patch(Git, 'method_missing')
    def test_id_abbrev(self, git):
        git.return_value = fixture('rev_list_commit_idabbrev')
        assert_equal('80f136f', self.repo.commit('80f136f500dfdb8c3e8abf4ae716f875f0a1b57f').id_abbrev)

    @patch(Git, 'method_missing')
    def test_diff(self, git):
        git.return_value = fixture('diff_p')
        
        diffs = Commit.diff(self.repo, 'master')
        
        assert_equal(15, len(diffs))
        
        assert_equal('.gitignore', diffs[0].a_path)
        assert_equal('.gitignore', diffs[0].b_path)
        assert_equal('4ebc8aea50e0a67e000ba29a30809d0a7b9b2666', diffs[0].a_commit.id)
        assert_equal('2dd02534615434d88c51307beb0f0092f21fd103', diffs[0].b_commit.id)
        assert_equal('100644', diffs[0].b_mode)
        assert_equal(False, diffs[0].new_file)
        assert_equal(False, diffs[0].deleted_file)
        assert_equal("--- a/.gitignore\n+++ b/.gitignore\n@@ -1 +1,2 @@\n coverage\n+pkg", diffs[0].diff)
        
        assert_equal('lib/grit/actor.rb', diffs[5].a_path)
        assert_equal(None, diffs[5].a_commit)
        assert_equal('f733bce6b57c0e5e353206e692b0e3105c2527f4', diffs[5].b_commit.id)
        assert_equal(True, diffs[5].new_file)

        assert_true(git.called)
        assert_equal(git.call_args, (('diff', 'master'), {'full_index': True}))

    @patch(Git, 'method_missing')
    def test_diff_with_two_commits(self, git):
        git.return_value = fixture('diff_2')
        
        diffs = Commit.diff(self.repo, '59ddc32', '13d27d5')
        
        assert_equal(3, len(diffs))
        
        assert_true(git.called)
        assert_equal(git.call_args, (('diff', '59ddc32', '13d27d5', '--', 'master'), {'full_index': True}))

    @patch(Git, 'method_missing')  
    def test_diff_with_files(self, git):
        git.return_value = fixture('diff_f')
        
        diffs = Commit.diff(self.repo, '59ddc32', ['lib'])
        
        assert_equal(1, len(diffs))
        assert_equal('lib/grit/diff.rb', diffs[0].a_path)
        
        assert_true(git.called)
        assert_equal(git.call_args, (('diff', '59ddc32', '--', 'lib'), {'full_index': True}))
  
    @patch(Git, 'method_missing')  
    def test_diff_with_two_commits_and_files(self, git):
        git.return_value = fixture('diff_2f')
        
        diffs = Commit.diff(self.repo, '59ddc32', '13d27d5', ['lib'])
    
        assert_equal(1, len(diffs))
        assert_equal('lib/grit/commit.rb', diffs[0].a_path)
        
        assert_true(git.called)
        assert_equal(git.call_args, (('diff', '59ddc32', '13d27d5', '--', 'lib'), {'full_index': True}))

    @patch(Git, 'method_missing')
    def test_diffs(self, git):
        git.return_value = fixture('diff_p')
                
        commit = Commit(self.repo, id='91169e1f5fa4de2eaea3f176461f5dc784796769', parents=['038af8c329ef7c1bae4568b98bd5c58510465493'])
        diffs = commit.diffs
        
        assert_equal(15, len(diffs))
        
        assert_equal('.gitignore', diffs[0].a_path)
        assert_equal('.gitignore', diffs[0].b_path)
        assert_equal('4ebc8aea50e0a67e000ba29a30809d0a7b9b2666', diffs[0].a_commit.id)
        assert_equal('2dd02534615434d88c51307beb0f0092f21fd103', diffs[0].b_commit.id)
        assert_equal('100644', diffs[0].b_mode)
        assert_equal(False, diffs[0].new_file)
        assert_equal(False, diffs[0].deleted_file)
        assert_equal("--- a/.gitignore\n+++ b/.gitignore\n@@ -1 +1,2 @@\n coverage\n+pkg", diffs[0].diff)
        
        assert_equal('lib/grit/actor.rb', diffs[5].a_path)
        assert_equal(None, diffs[5].a_commit)
        assert_equal('f733bce6b57c0e5e353206e692b0e3105c2527f4', diffs[5].b_commit.id)
        assert_equal(True, diffs[5].new_file)
        
        assert_true(git.called)
        assert_equal(git.call_args, (('diff', '038af8c329ef7c1bae4568b98bd5c58510465493', 
                                              '91169e1f5fa4de2eaea3f176461f5dc784796769', 
                                              '--', '59ddc32', '13d27d5', '--', 'master'), {'full_index': True}))        

    @patch(Git, 'method_missing')  
    def test_diffs_on_initial_import(self, git):
        git.return_value = fixture('diff_i')
        
        commit = Commit(self.repo, id='634396b2f541a9f2d58b00be1a07f0c358b999b3')
        commit.__bake_it__()
        diffs = commit.diffs
        
        assert_equal(10, len(diffs))
        
        assert_equal('History.txt', diffs[0].a_path)
        assert_equal('History.txt', diffs[0].b_path)
        assert_equal(None, diffs[0].a_commit)
        assert_equal(None, diffs[0].b_mode)
        assert_equal('81d2c27608b352814cbe979a6acd678d30219678', diffs[0].b_commit.id)
        assert_equal(True, diffs[0].new_file)
        assert_equal(False, diffs[0].deleted_file)
        assert_equal("--- /dev/null\n+++ b/History.txt\n@@ -0,0 +1,5 @@\n+== 1.0.0 / 2007-10-09\n+\n+* 1 major enhancement\n+  * Birthday!\n+", diffs[0].diff)
        
        assert_equal('lib/grit.rb', diffs[5].a_path)
        assert_equal(None, diffs[5].a_commit)
        assert_equal('32cec87d1e78946a827ddf6a8776be4d81dcf1d1', diffs[5].b_commit.id)
        assert_equal(True, diffs[5].new_file)
        
        assert_true(git.called)
        assert_equal(git.call_args, (('show', '634396b2f541a9f2d58b00be1a07f0c358b999b3'), {'full_index': True, 'pretty': 'raw'}))
  
    @patch(Git, 'method_missing')  
    def test_diffs_on_initial_import_with_empty_commit(self, git):
        git.return_value = fixture('show_empty_commit')
        
        commit = Commit(self.repo, id='634396b2f541a9f2d58b00be1a07f0c358b999b3')
        diffs = commit.diffs
        
        assert_equal([], diffs)
        
        assert_true(git.called)
        assert_equal(git.call_args, (('show', '634396b2f541a9f2d58b00be1a07f0c358b999b3'), {'full_index': True, 'pretty': 'raw'}))
  
    @patch(Git, 'method_missing')  
    def test_diffs_with_mode_only_change(self, git):
        git.return_value = fixture('diff_mode_only')
        
        commit = Commit(self.repo, id='91169e1f5fa4de2eaea3f176461f5dc784796769')
        commit.__bake_it__()
        diffs = commit.diffs
        
        assert_equal(23, len(diffs))
        assert_equal('100644', diffs[0].a_mode)
        assert_equal('100755', diffs[0].b_mode)
        
        assert_true(git.called)
        assert_equal(git.call_args, (('show', '91169e1f5fa4de2eaea3f176461f5dc784796769'), {'full_index': True, 'pretty': 'raw'}))

    @patch(Git, 'method_missing')  
    def test_stats(self, git):
        git.return_value = fixture('diff_numstat')
        
        commit = Commit(self.repo, id='634396b2f541a9f2d58b00be1a07f0c358b999b3')
        commit.__bake_it__()
        stats = commit.stats
        
        keys = stats.files.keys()
        keys.sort()
        assert_equal(["a.txt", "b.txt"], keys)
        
        assert_true(git.called)
        assert_equal(git.call_args, (('diff', '634396b2f541a9f2d58b00be1a07f0c358b999b3'), {'numstat': True}))
  
    def test_str(self):
        commit = Commit(self.repo, id='abc')
        assert_equal ("abc", str(commit))
  
    def test_repr(self):
        commit = Commit(self.repo, id='abc')
        assert_equal('<GitPython.Commit "abc">', repr(commit))
