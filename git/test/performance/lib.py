"""Contains library functions"""
import os
from git.test.lib import *
import shutil
import tempfile

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


#{ Utilities
def resolve_or_fail(env_var):
	""":return: resolved environment variable or raise EnvironmentError"""
	try:
		return os.environ[env_var]
	except KeyError:
		raise EnvironmentError("Please set the %r envrionment variable and retry" % env_var)
	# END exception handling

#} END utilities


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
	
	@classmethod
	def setUpAll(cls):
		super(TestBigRepoR, cls).setUpAll()
		repo_path = resolve_or_fail(k_env_git_repo)
		cls.gitrorepo = Repo(repo_path, odbt=GitCmdObjectDB)
		cls.puregitrorepo = Repo(repo_path, odbt=GitDB)


class TestBigRepoRW(TestBigRepoR):
	"""As above, but provides a big repository that we can write to.
	
	Provides ``self.gitrwrepo`` and ``self.puregitrwrepo``"""
	
	@classmethod
	def setUpAll(cls):
		super(TestBigRepoRW, cls).setUpAll()
		dirname = tempfile.mktemp()
		os.mkdir(dirname)
		cls.gitrwrepo = cls.gitrorepo.clone(dirname, shared=True, bare=True, odbt=GitCmdObjectDB)
		cls.puregitrwrepo = Repo(dirname, odbt=GitDB)
	
	@classmethod
	def tearDownAll(cls):
		shutil.rmtree(cls.gitrwrepo.working_dir)
		
#} END base classes
