"""Contains library functions"""
import os
from test.testlib import *
import shutil
import tempfile

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
	
	* gitrepo
	
	 * Read-Only git repository - actually the repo of git itself"""
	 
	#{ Invariants
	head_sha_2k = '235d521da60e4699e5bd59ac658b5b48bd76ddca'
	head_sha_50 = '32347c375250fd470973a5d76185cac718955fd5'
	#} END invariants 
	
	@classmethod
	def setUpAll(cls):
		super(TestBigRepoR, cls).setUpAll()
		cls.gitrorepo = Repo(resolve_or_fail(k_env_git_repo))


class TestBigRepoRW(TestBigRepoR):
	"""As above, but provides a big repository that we can write to.
	
	Provides ``self.gitrwrepo``"""
	
	@classmethod
	def setUpAll(cls):
		super(TestBigRepoRW, cls).setUpAll()
		dirname = tempfile.mktemp()
		os.mkdir(dirname)
		cls.gitrwrepo = cls.gitrorepo.clone(dirname, shared=True, bare=True)
	
	@classmethod
	def tearDownAll(cls):
		shutil.rmtree(cls.gitrwrepo.working_dir)
		
#} END base classes
