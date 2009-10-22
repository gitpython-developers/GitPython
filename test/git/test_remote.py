# test_remote.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *

class TestRemote(TestBase):
	
	@with_rw_and_rw_remote_repo('0.1.6')
	def test_base(self, rw_repo, remote_repo):
		num_remotes = 0
		remote_set = set()
		for remote in rw_repo.remotes:
			num_remotes += 1
			assert remote == remote
			assert str(remote) != repr(remote)
			remote_set.add(remote)
			remote_set.add(remote)	# should already exist
			
			# REFS 
			refs = remote.refs
			assert refs
			for ref in refs:
				assert ref.remote_name == remote.name
				assert ref.remote_branch
			# END for each ref
			
			# OPTIONS
			# cannot use 'fetch' key anymore as it is now a method
			for opt in ("url", ):
				val = getattr(remote, opt)
				reader = remote.config_reader
				assert reader.get(opt) == val
				
				# unable to write with a reader
				self.failUnlessRaises(IOError, reader.set, opt, "test")
				
				# change value
				writer = remote.config_writer
				new_val = "myval"
				writer.set(opt, new_val)
				assert writer.get(opt) == new_val
				writer.set(opt, val)
				assert writer.get(opt) == val
				del(writer)
				assert getattr(remote, opt) == val
			# END for each default option key 
			
			# RENAME 
			other_name = "totally_other_name"
			prev_name = remote.name
			assert remote.rename(other_name) == remote
			assert prev_name != remote.name
			# multiple times
			for time in range(2):
				assert remote.rename(prev_name).name == prev_name
			# END for each rename ( back to prev_name )
			
			remote.fetch()
			self.failUnlessRaises(GitCommandError, remote.pull)
			remote.pull('master')
			remote.update()
			self.fail("test push once there is a test-repo")
		# END for each remote
		assert num_remotes
		assert num_remotes == len(remote_set)
		
		origin = rw_repo.remote('origin')
		assert origin == rw_repo.remotes.origin
		
	@with_bare_rw_repo
	def test_creation_and_removal(self, bare_rw_repo):
		new_name = "test_new_one"
		arg_list = (new_name, "git@server:hello.git")
		remote = Remote.create(bare_rw_repo, *arg_list )
		assert remote.name == "test_new_one"
		
		# create same one again
		self.failUnlessRaises(GitCommandError, Remote.create, bare_rw_repo, *arg_list)
		
		Remote.remove(bare_rw_repo, new_name)
		
		for remote in bare_rw_repo.remotes:
			if remote.name == new_name:
				raise AssertionError("Remote removal failed")
			# END if deleted remote matches existing remote's name
		# END for each remote
		
		
	
