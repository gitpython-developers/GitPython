"""Contains library functions"""
import os
from git.test.lib import *
import shutil
import tempfile
import logging

from git.db import (
    GitCmdObjectDB,
    GitDB
)

from git import (
    Repo
)

#{ Invvariants
k_env_git_repo = "GIT_PYTHON_TEST_GIT_REPO_BASE"
#} END invariants


#{ Base Classes

class TestBigRepoR(TestBase):

    """TestCase providing access to readonly 'big' repositories using the following
    member variables:

    * gitrorepo

     * Read-Only git repository - actually the repo of git itself

    * puregitrorepo

     * As gitrepo, but uses pure python implementation
    """

    #{ Invariants
    head_sha_2k = '235d521da60e4699e5bd59ac658b5b48bd76ddca'
    head_sha_50 = '32347c375250fd470973a5d76185cac718955fd5'
    #} END invariants

    def setUp(self):
        try:
            super(TestBigRepoR, self).setUp()
        except AttributeError:
            pass

        repo_path = os.environ.get(k_env_git_repo)
        if repo_path is None:
            logging.info("You can set the %s environment variable to a .git repository of your choice - defaulting to the gitpython repository", k_env_git_repo)
            repo_path = os.path.dirname(__file__)
        # end set some repo path
        self.gitrorepo = Repo(repo_path, odbt=GitCmdObjectDB)
        self.puregitrorepo = Repo(repo_path, odbt=GitDB)


class TestBigRepoRW(TestBigRepoR):

    """As above, but provides a big repository that we can write to.

    Provides ``self.gitrwrepo`` and ``self.puregitrwrepo``"""

    def setUp(self):
        try:
            super(TestBigRepoRW, self).setUp()
        except AttributeError:
            pass
        dirname = tempfile.mktemp()
        os.mkdir(dirname)
        self.gitrwrepo = self.gitrorepo.clone(dirname, shared=True, bare=True, odbt=GitCmdObjectDB)
        self.puregitrwrepo = Repo(dirname, odbt=GitDB)

    def tearDown(self):
        shutil.rmtree(self.gitrwrepo.working_dir)

#} END base classes
