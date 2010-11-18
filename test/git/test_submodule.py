# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git.exc import *
from git.objects.submodule.base import Submodule
from git.objects.submodule.root import RootModule
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
		assert smold == sm					# the name is still the same
		
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
			assert sm.remove(dry_run=True) is sm
			assert sm.module_exists()
			sm.remove(force=True, dry_run=True)
			assert sm.module_exists()
			
			# but ... we have untracked files in the child submodule
			fn = join_path_native(csm.module().working_tree_dir, "newfile")
			open(fn, 'w').write("hi")
			self.failUnlessRaises(InvalidGitRepositoryError, sm.remove)
			
			# forcibly delete the child repository
			assert csm.remove(force=True) is csm
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
			nsm.set_parent_commit(rwrepo.head.commit)
			osm.set_parent_commit(rwrepo.head.commit)
			
			# MOVE MODULE
			#############
			# invalid inptu
			self.failUnlessRaises(ValueError, nsm.move, 'doesntmatter', module=False, configuration=False)
			
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
		
	@with_rw_repo(k_subm_current, bare=False)
	def test_root_module(self, rwrepo):
		# Can query everything without problems
		rm = RootModule(self.rorepo)
		assert rm.module() is self.rorepo
		
		# try attributes
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
		rsms = list(rm.traverse())
		assert len(rsms) == 2			# gitdb and async, async being a child of gitdb
		
		# cannot set the parent commit as root module's path didn't exist
		self.failUnlessRaises(ValueError, rm.set_parent_commit, 'HEAD')
		
		# TEST UPDATE
		#############
		# setup commit which remove existing, add new and modify existing submodules
		rm = RootModule(rwrepo)
		assert len(rm.children()) == 1
		
		# modify path without modifying the index entry
		# ( which is what the move method would do properly )
		#==================================================
		sm = rm.children()[0]
		pp = "path/prefix"
		fp = join_path_native(pp, sm.path)
		prep = sm.path
		assert not sm.module_exists()				# was never updated after rwrepo's clone
		
		# assure we clone from a local source 
		sm.config_writer().set_value('url', join_path_native(self.rorepo.working_tree_dir, sm.path))
		sm.update(recursive=False)
		assert sm.module_exists()
		sm.config_writer().set_value('path', fp)	# change path to something with prefix AFTER url change
		
		# update fails as list_items in such a situations cannot work, as it cannot
		# find the entry at the changed path
		self.failUnlessRaises(InvalidGitRepositoryError, rm.update, recursive=False)
		
		# move it properly - doesn't work as it its path currently points to an indexentry
		# which doesn't exist ( move it to some path, it doesn't matter here )
		self.failUnlessRaises(InvalidGitRepositoryError, sm.move, pp)
		# reset the path(cache) to where it was, now it works
		sm.path = prep
		sm.move(fp, module=False)		# leave it at the old location
		
		assert not sm.module_exists()
		cpathchange = rwrepo.index.commit("changed sm path") # finally we can commit
		
		# update puts the module into place
		rm.update(recursive=False)
		sm.set_parent_commit(cpathchange)
		assert sm.module_exists()
		
		# add submodule
		#================
		nsmn = "newsubmodule"
		nsmp = "submrepo"
		async_url = join_path_native(self.rorepo.working_tree_dir, rsms[0].path, rsms[1].path)
		nsm = Submodule.add(rwrepo, nsmn, nsmp, url=async_url)
		csmadded = rwrepo.index.commit("Added submodule")
		nsm.set_parent_commit(csmadded)
		assert nsm.module_exists()
		# in our case, the module should not exist, which happens if we update a parent
		# repo and a new submodule comes into life
		nsm.remove(configuration=False, module=True)
		assert not nsm.module_exists() and nsm.exists()
		
		rm.update(recursive=False)
		assert nsm.module_exists()
		
		
		
		# remove submodule - the previous one
		#====================================
		sm.set_parent_commit(csmadded)
		smp = sm.abspath
		assert not sm.remove(module=False).exists()
		assert os.path.isdir(smp)			# module still exists
		csmremoved = rwrepo.index.commit("Removed submodule")
		
		# an update will remove the module
		rm.update(recursive=False)
		assert not os.path.isdir(smp)
		
		
		# change url 
		#=============
		# to the first repository, this way we have a fast checkout, and a completely different 
		# repository at the different url
		nsm.set_parent_commit(csmremoved)
		nsmurl = join_path_native(self.rorepo.working_tree_dir, rsms[0].path)
		nsm.config_writer().set_value('url', nsmurl)
		csmpathchange = rwrepo.index.commit("changed url")
		nsm.set_parent_commit(csmpathchange)
		
		prev_commit = nsm.module().head.commit
		rm.update(recursive=False)
		assert nsm.module().remotes.origin.url == nsmurl
		# head changed, as the remote url and its commit changed
		assert prev_commit != nsm.module().head.commit
		
		# add the submodule's changed commit to the index, which is what the
		# user would do
		# beforehand, update our instance's binsha with the new one
		nsm.binsha = nsm.module().head.commit.binsha
		rwrepo.index.add([nsm])
		
		# change branch
		#=================
		# we only have one branch, so we switch to a virtual one, and back 
		# to the current one to trigger the difference
		cur_branch = nsm.branch
		nsmm = nsm.module()
		prev_commit = nsmm.head.commit
		for branch in ("some_virtual_branch", cur_branch.name):
			nsm.config_writer().set_value(Submodule.k_head_option, branch)
			csmbranchchange = rwrepo.index.commit("changed branch to %s" % branch)
			nsm.set_parent_commit(csmbranchchange)
		# END for each branch to change
		
		# Lets remove our tracking branch to simulate some changes
		nsmmh = nsmm.head
		assert nsmmh.ref.tracking_branch() is None					# never set it up until now
		assert not nsmmh.is_detached
		
		rm.update(recursive=False)
		
		assert nsmmh.ref.tracking_branch() is not None
		assert not nsmmh.is_detached
		
		# recursive update
		# =================
		# finally we recursively update a module, just to run the code at least once
		# remove the module so that it has more work
		assert len(nsm.children()) == 1
		assert nsm.exists() and nsm.module_exists() and len(nsm.children()) == 1
		# assure we pull locally only
		nsmc = nsm.children()[0] 
		nsmc.config_writer().set_value('url', async_url)
		rm.update(recursive=True)
		
		assert len(nsm.children()) == 1 and nsmc.module_exists() 
		
