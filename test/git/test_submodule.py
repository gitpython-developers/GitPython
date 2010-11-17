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
		assert sm.path == sm.name					# for now, this is True
		assert sm.url == 'git://gitorious.org/git-python/gitdb.git'
		assert sm.branch.name == 'master'			# its unset in this case
		assert sm.parent_commit == rwrepo.head.commit
		# size is always 0
		assert sm.size == 0
		
		# some commits earlier we still have a submodule, but its at a different commit
		smold = Submodule.iter_items(rwrepo, self.k_subm_changed).next()
		assert smold.binsha != sm.binsha
		assert smold != sm
		
		# force it to reread its information
		del(smold._url)
		smold.url == sm.url
		
		# test config_reader/writer methods
		sm.config_reader()
		new_smclone_path = None				# keep custom paths for later 
		new_csmclone_path = None				# 
		if rwrepo.bare:
			self.failUnlessRaises(InvalidGitRepositoryError, sm.config_writer)
		else:
			writer = sm.config_writer()
			# for faster checkout, set the url to the local path
			new_smclone_path = to_native_path_linux(join_path_native(self.rorepo.working_tree_dir, sm.path))
			writer.set_value('url', new_smclone_path)
			del(writer)
			assert sm.config_reader().get_value('url') == new_smclone_path
			assert sm.url == new_smclone_path
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
		
		# TEST UPDATE
		##############
		# module retrieval is not always possible
		if rwrepo.bare:
			self.failUnlessRaises(InvalidGitRepositoryError, sm.module)
			self.failUnlessRaises(InvalidGitRepositoryError, sm.remove)
			self.failUnlessRaises(InvalidGitRepositoryError, sm.add, rwrepo, 'here', 'there')
		else:
			# its not checked out in our case
			self.failUnlessRaises(InvalidGitRepositoryError, sm.module)
			assert not sm.module_exists()
			
			# currently there is only one submodule
			assert len(list(rwrepo.iter_submodules())) == 1
			
			# TEST ADD
			###########
			# preliminary tests
			# adding existing returns exactly the existing
			sma = Submodule.add(rwrepo, sm.name, sm.path)
			assert sma.path == sm.path
			
			# no url and no module at path fails
			self.failUnlessRaises(ValueError, Submodule.add, rwrepo, "newsubm", "pathtorepo", url=None)
			
			# CONTINUE UPDATE
			#################
			
			# lets update it - its a recursive one too
			newdir = os.path.join(sm.abspath, 'dir')
			os.makedirs(newdir)
			
			# update fails if the path already exists non-empty
			self.failUnlessRaises(OSError, sm.update)
			os.rmdir(newdir)
			
			assert sm.update() is sm
			sm_repopath = sm.path				# cache for later
			assert sm.module_exists()
			assert isinstance(sm.module(), git.Repo)
			assert sm.module().working_tree_dir == sm.abspath
			
			# INTERLEAVE ADD TEST
			#####################
			# url must match the one in the existing repository ( if submodule name suggests a new one )
			# or we raise
			self.failUnlessRaises(ValueError, Submodule.add, rwrepo, "newsubm", sm.path, "git://someurl/repo.git")
			
			
			# CONTINUE UPDATE
			#################
			# we should have setup a tracking branch, which is also active
			assert sm.module().head.ref.tracking_branch() is not None
			
			# delete the whole directory and re-initialize
			shutil.rmtree(sm.abspath)
			sm.update(recursive=False)
			assert len(list(rwrepo.iter_submodules())) == 2
			assert len(sm.children()) == 1			# its not checked out yet
			csm = sm.children()[0]
			assert not csm.module_exists()
			csm_repopath = csm.path
			
			# adjust the path of the submodules module to point to the local destination
			new_csmclone_path = to_native_path_linux(join_path_native(self.rorepo.working_tree_dir, sm.path, csm.path))
			csm.config_writer().set_value('url', new_csmclone_path)
			assert csm.url == new_csmclone_path
			
			# update recuesively again
			sm.update(recursive=True)
			
			# tracking branch once again
			csm.module().head.ref.tracking_branch() is not None
			
			# this flushed in a sub-submodule
			assert len(list(rwrepo.iter_submodules())) == 2
			
			
			# reset both heads to the previous version, verify that to_latest_revision works
			for repo in (csm.module(), sm.module()):
				repo.head.reset('HEAD~1', working_tree=1)
			# END for each repo to reset
			
			sm.update(recursive=True, to_latest_revision=True)
			for repo in (sm.module(), csm.module()):
				assert repo.head.commit == repo.head.ref.tracking_branch().commit
			# END for each repo to check
			
			# if the head is detached, it still works ( but warns )
			smref = sm.module().head.ref
			sm.module().head.ref = 'HEAD~1'
			# if there is no tracking branch, we get a warning as well
			csm_tracking_branch = csm.module().head.ref.tracking_branch()
			csm.module().head.ref.set_tracking_branch(None)
			sm.update(recursive=True, to_latest_revision=True)
			
			# undo the changes
			sm.module().head.ref = smref
			csm.module().head.ref.set_tracking_branch(csm_tracking_branch)
			
			# REMOVAL OF REPOSITOTRY
			########################
			# must delete something
			self.failUnlessRaises(ValueError, csm.remove, module=False, configuration=False)
			# We have modified the configuration, hence the index is dirty, and the
			# deletion will fail
			# NOTE: As we did  a few updates in the meanwhile, the indices where reset
			# Hence we restore some changes
			sm.config_writer().set_value("somekey", "somevalue")
			csm.config_writer().set_value("okey", "ovalue")
			self.failUnlessRaises(InvalidGitRepositoryError, sm.remove)
			# if we remove the dirty index, it would work
			sm.module().index.reset()
			# still, we have the file modified
			self.failUnlessRaises(InvalidGitRepositoryError, sm.remove, dry_run=True)
			sm.module().index.reset(working_tree=True)
			
			# this would work
			sm.remove(dry_run=True)
			assert sm.module_exists()
			sm.remove(force=True, dry_run=True)
			assert sm.module_exists()
			
			# but ... we have untracked files in the child submodule
			fn = join_path_native(csm.module().working_tree_dir, "newfile")
			open(fn, 'w').write("hi")
			self.failUnlessRaises(InvalidGitRepositoryError, sm.remove)
			
			# forcibly delete the child repository
			csm.remove(force=True)
			assert not csm.exists()
			assert not csm.module_exists()
			assert len(sm.children()) == 0
			# now we have a changed index, as configuration was altered.
			# fix this
			sm.module().index.reset(working_tree=True)
			
			# now delete only the module of the main submodule
			assert sm.module_exists()
			sm.remove(configuration=False)
			assert sm.exists()
			assert not sm.module_exists()
			assert sm.config_reader().get_value('url')
			
			# delete the rest
			sm.remove()
			assert not sm.exists()
			assert not sm.module_exists()
			
			assert len(rwrepo.submodules) == 0
			
			# ADD NEW SUBMODULE
			###################
			# add a simple remote repo - trailing slashes are no problem
			smid = "newsub"
			osmid = "othersub"
			nsm = Submodule.add(rwrepo, smid, sm_repopath, new_smclone_path+"/", None, no_checkout=True)
			assert nsm.name == smid
			assert nsm.module_exists()
			assert nsm.exists()
			# its not checked out
			assert not os.path.isfile(join_path_native(nsm.module().working_tree_dir, Submodule.k_modules_file))
			assert len(rwrepo.submodules) == 1
			
			# add another submodule, but into the root, not as submodule
			osm = Submodule.add(rwrepo, osmid, csm_repopath, new_csmclone_path, Submodule.k_head_default)
			assert osm != nsm
			assert osm.module_exists()
			assert osm.exists()
			assert os.path.isfile(join_path_native(osm.module().working_tree_dir, 'setup.py'))
			
			assert len(rwrepo.submodules) == 2
			
			# commit the changes, just to finalize the operation
			rwrepo.index.commit("my submod commit")
			assert len(rwrepo.submodules) == 2
			
			# needs update as the head changed, it thinks its in the history 
			# of the repo otherwise
			nsm._parent_commit = rwrepo.head.commit
			osm._parent_commit = rwrepo.head.commit
			
			# MOVE MODULE
			#############
			# renaming to the same path does nothing
			assert nsm.move(sm.path) is nsm
			
			# rename a module
			nmp = join_path_native("new", "module", "dir") + "/" # new module path
			pmp = nsm.path
			abspmp = nsm.abspath
			assert nsm.move(nmp) is nsm
			nmp = nmp[:-1]			# cut last /
			assert nsm.path == nmp
			assert rwrepo.submodules[0].path == nmp
			
			# move it back - but there is a file now - this doesn't work
			# as the empty directories where removed.
			self.failUnlessRaises(IOError, open, abspmp, 'w')
			
			mpath = 'newsubmodule'
			absmpath = join_path_native(rwrepo.working_tree_dir, mpath)
			open(absmpath, 'w').write('')
			self.failUnlessRaises(ValueError, nsm.move, mpath)
			os.remove(absmpath)
			
			# now it works, as we just move it back
			nsm.move(pmp)
			assert nsm.path == pmp
			assert rwrepo.submodules[0].path == pmp
			
			# TODO lowprio: test remaining exceptions ... for now its okay, the code looks right
			
			# REMOVE 'EM ALL
			################
			# if a submodule's repo has no remotes, it can't be added without an explicit url
			osmod = osm.module()
			
			osm.remove(module=False)
			for remote in osmod.remotes:
				remote.remove(osmod, remote.name)
			assert not osm.exists()
			self.failUnlessRaises(ValueError, Submodule.add, rwrepo, osmid, csm_repopath, url=None)   
		# END handle bare mode
		
		# Error if there is no submodule file here
		self.failUnlessRaises(IOError, Submodule._config_parser, rwrepo, rwrepo.commit(self.k_no_subm_tag), True)
		
	
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
		
