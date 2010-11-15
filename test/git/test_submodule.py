# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git.exc import *
from git.objects.submodule import *
from git.util import to_native_path_linux, join_path_native
import shutil
import git
import os

class TestSubmodule(TestBase):

	k_subm_current = "00ce31ad308ff4c7ef874d2fa64374f47980c85c"
	k_subm_changed = "394ed7006ee5dc8bddfd132b64001d5dfc0ffdd3"
	k_no_subm_tag = "0.1.6"
	

	def _do_base_tests(self, rwrepo):
		"""Perform all tests in the given repository, it may be bare or nonbare"""
		# manual instantiation
		smm = Submodule(rwrepo, "\0"*20)
		# name needs to be set in advance
		self.failUnlessRaises(AttributeError, getattr, smm, 'name') 
		
		# iterate - 1 submodule
		sms = Submodule.list_items(rwrepo, self.k_subm_current)
		assert len(sms) == 1
		sm = sms[0]
		
		# at a different time, there is None
		assert len(Submodule.list_items(rwrepo, self.k_no_subm_tag)) == 0
		
		assert sm.path == 'lib/git/ext/gitdb'
		assert sm.path == sm.name				# for now, this is True
		assert sm.url == 'git://gitorious.org/git-python/gitdb.git'
		assert sm.branch == 'master'			# its unset in this case
		assert sm.parent_commit == rwrepo.head.commit
		# size is invalid
		self.failUnlessRaises(ValueError, getattr, sm, 'size')
		
		# some commits earlier we still have a submodule, but its at a different commit
		smold = Submodule.iter_items(rwrepo, self.k_subm_changed).next()
		assert smold.binsha != sm.binsha
		assert smold != sm
		
		# force it to reread its information
		del(smold._url)
		smold.url == sm.url
		
		# test config_reader/writer methods
		sm.config_reader()
		if rwrepo.bare:
			self.failUnlessRaises(InvalidGitRepositoryError, sm.config_writer)
		else:
			writer = sm.config_writer()
			# for faster checkout, set the url to the local path
			new_path = to_native_path_linux(join_path_native(self.rorepo.working_tree_dir, sm.path))
			writer.set_value('url', new_path)
			del(writer)
			assert sm.config_reader().get_value('url') == new_path
			assert sm.url == new_path
		# END handle bare repo
		smold.config_reader()
		
		# cannot get a writer on historical submodules
		if not rwrepo.bare:
			self.failUnlessRaises(ValueError, smold.config_writer)
		# END handle bare repo
		
		# make the old into a new
		prev_parent_commit = smold.parent_commit
		assert smold.set_parent_commit(self.k_subm_current) is smold 
		assert smold.parent_commit != prev_parent_commit
		assert smold.binsha == sm.binsha
		smold.set_parent_commit(prev_parent_commit)
		assert smold.binsha != sm.binsha
		
		# raises if the sm didn't exist in new parent - it keeps its 
		# parent_commit unchanged
		self.failUnlessRaises(ValueError, smold.set_parent_commit, self.k_no_subm_tag)
		
		# TEST TODO: if a path in the gitmodules file, but not in the index, it raises
		
		# module retrieval is not always possible
		if rwrepo.bare:
			self.failUnlessRaises(InvalidGitRepositoryError, sm.module)
		else:
			# its not checked out in our case
			self.failUnlessRaises(InvalidGitRepositoryError, sm.module)
			
			# lets update it - its a recursive one too
			newdir = os.path.join(sm.module_path(), 'dir')
			os.makedirs(newdir)
			
			# update fails if the path already exists non-empty
			self.failUnlessRaises(OSError, sm.update)
			os.rmdir(newdir)
			
			assert sm.update() is sm
			assert isinstance(sm.module(), git.Repo)
			assert sm.module().working_tree_dir == sm.module_path()
			
			# delete the whole directory and re-initialize
			shutil.rmtree(sm.module_path())
			sm.update(recursive=True)
		# END handle bare mode
		
		
		# Error if there is no submodule file here
		self.failUnlessRaises(IOError, Submodule._config_parser, rwrepo, rwrepo.commit(self.k_no_subm_tag), True)
		
		# TODO: Handle bare/unbare
		# latest submodules write changes into the .gitmodules files
		
		# uncached path/url - retrieves information from .gitmodules file
		
		# index stays up-to-date with the working tree .gitmodules file
		
		# changing the root_tree yields new values when querying them (i.e. cache is cleared)
		
		
		
		
		# set_parent_commit fails if tree has no gitmodule file
		
		
		
		if rwrepo.bare:
			# module fails
			pass
		else:
			# get the module repository
			pass
		# END bare handling
		
		# Writing of historical submodule configurations must not work
	
	@with_rw_repo(k_subm_current)
	def test_base_rw(self, rwrepo):
		self._do_base_tests(rwrepo)
		
	@with_rw_repo(k_subm_current, bare=True)
	def test_base_bare(self, rwrepo):
		self._do_base_tests(rwrepo)
		
	def test_root_module(self):
		# Can query everything without problems
		rm = RootModule(self.rorepo)
		assert rm.module() is self.rorepo
		
		rm.binsha
		rm.mode
		rm.path
		assert rm.name == rm.k_root_name
		assert rm.parent_commit == self.rorepo.head.commit
		rm.url
		rm.branch
		
		assert len(rm.list_items(rm.module())) == 1
		rm.config_reader()
		rm.config_writer()
		
		# deep traversal gitdb / async
		assert len(list(rm.traverse())) == 2
		
		# cannot set the parent commit as repo name doesn't exist
		self.failUnlessRaises(ValueError, rm.set_parent_commit, 'HEAD')
		
