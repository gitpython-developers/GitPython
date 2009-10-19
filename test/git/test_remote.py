# test_remote.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *

class TestRemote(TestCase):
	
	@classmethod
	def setUpAll(cls):
		cls.repo = Repo(GIT_REPO)
		
	def test_base(self):
		num_remotes = 0
		for remote in self.repo.remotes:
			num_remotes += 1
			assert str(remote) != repr(remote)
			
			
			refs = remote.refs
			assert refs
			for ref in refs:
				assert ref.remote_name == remote.name
				assert ref.remote_branch
			# END for each ref
			
			# test rename 
			other_name = "totally_other_name"
			prev_name = remote.name
			assert remote.rename(other_name) == remote
			assert prev_name != remote.name
			# multiple times
			for time in range(2):
				assert remote.rename(prev_name).name == prev_name
			# END for each rename ( back to prev_name )
			
			remote.update()
			
		# END for each remote
		assert num_remotes
		
	def test_creation_and_removal(self):
		self.fail( "Test remote creation/removal" )
		
	
