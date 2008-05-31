from test.testlib import *
from git import *

class TestHead(object):
    def setup(self):
        self.repo = Repo(GIT_REPO)

    @patch(Git, 'method_missing')  
    def test_repr(self, git):
        git.return_value = fixture('for_each_ref')
        
        head = self.repo.heads[0]
        
        assert_equal('<GitPython.Head "%s">' % head.name, repr(head))
        
        assert_true(git.called)
        assert_equal(git.call_args, (('for_each_ref', 'refs/heads'), {'sort': 'committerdate', 'format': '%(refname)%00%(objectname)'}))
