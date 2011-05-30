"""Provide customized obhject testing facilities"""

from git.test.lib import (
							rorepo_dir,
							TestBase,
							assert_equal,
							assert_not_equal,
							with_rw_repo,
							StringProcessAdapter,
						)
from git.repo import Repo

class TestObjectBase(TestBase):
	"""Provides a default read-only repository in the rorepo member"""
	
	@classmethod
	def setUpAll(cls):
		cls.rorepo = Repo(rorepo_dir())
