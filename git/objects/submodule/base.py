import util
from util import (
					mkhead,
					sm_name, 
					sm_section, 
					unbare_repo, 
					SubmoduleConfigParser,
					find_first_remote_branch
				)
from git.objects.util import Traversable
from StringIO import StringIO					# need a dict to set bloody .name field
from git.util import (
						Iterable, 
						join_path_native, 
						to_native_path_linux,
						RemoteProgress,
						rmtree
					)

from git.config import SectionConstraint
from git.exc import (
					InvalidGitRepositoryError, 
					NoSuchPathError
					)

import stat
import git

import os
import sys
import time

__all__ = ["Submodule", "UpdateProgress"]


class UpdateProgress(RemoteProgress):
	"""Class providing detailed progress information to the caller who should 
	derive from it and implement the ``update(...)`` message"""
	CLONE, FETCH, UPDWKTREE = [1 << x for x in range(RemoteProgress._num_op_codes, RemoteProgress._num_op_codes+3)]
	_num_op_codes = RemoteProgress._num_op_codes + 3
	
	__slots__ = tuple()
	
	
BEGIN = UpdateProgress.BEGIN
END = UpdateProgress.END
CLONE = UpdateProgress.CLONE
FETCH = UpdateProgress.FETCH
UPDWKTREE = UpdateProgress.UPDWKTREE


# IndexObject comes via util module, its a 'hacky' fix thanks to pythons import 
# mechanism which cause plenty of trouble of the only reason for packages and
# modules is refactoring - subpackages shoudn't depend on parent packages
class Submodule(util.IndexObject, Iterable, Traversable):
	"""Implements access to a git submodule. They are special in that their sha
	represents a commit in the submodule's repository which is to be checked out
	at the path of this instance. 
	The submodule type does not have a string type associated with it, as it exists
	solely as a marker in the tree and index.
	
	All methods work in bare and non-bare repositories."""
	
	_id_attribute_ = "name"
	k_modules_file = '.gitmodules'
	k_head_option = 'branch'
	k_head_default = 'master'
	k_default_mode = stat.S_IFDIR | stat.S_IFLNK		# submodules are directories with link-status
	
	# this is a bogus type for base class compatability
	type = 'submodule'
	
	__slots__ = ('_parent_commit', '_url', '_branch_path', '_name', '__weakref__')
	_cache_attrs = ('path', '_url', '_branch_path')
	
	def __init__(self, repo, binsha, mode=None, path=None, name = None, parent_commit=None, url=None, branch_path=None):
		"""Initialize this instance with its attributes. We only document the ones 
		that differ from ``IndexObject``
		
		:param repo: Our parent repository
		:param binsha: binary sha referring to a commit in the remote repository, see url parameter
		:param parent_commit: see set_parent_commit()
		:param url: The url to the remote repository which is the submodule
		:param branch_path: full (relative) path to ref to checkout when cloning the remote repository"""
		super(Submodule, self).__init__(repo, binsha, mode, path)
		self.size = 0
		if parent_commit is not None:
			self._parent_commit = parent_commit
		if url is not None:
			self._url = url
		if branch_path is not None:
			assert isinstance(branch_path, basestring)
			self._branch_path = branch_path
		if name is not None:
			self._name = name
	
	def _set_cache_(self, attr):
		if attr == '_parent_commit':
			# set a default value, which is the root tree of the current head
			self._parent_commit = self.repo.commit()
		elif attr in ('path', '_url', '_branch_path'):
			reader = self.config_reader()
			# default submodule values
			self.path = reader.get_value('path')
			self._url = reader.get_value('url')
			# git-python extension values - optional
			self._branch_path = reader.get_value(self.k_head_option, git.Head.to_full_path(self.k_head_default))
		elif attr == '_name':
			raise AttributeError("Cannot retrieve the name of a submodule if it was not set initially")
		else:
			super(Submodule, self)._set_cache_(attr)
		# END handle attribute name
		
	def _get_intermediate_items(self, item):
		""":return: all the submodules of our module repository"""
		try:
			return type(self).list_items(item.module())
		except InvalidGitRepositoryError:
			return list()
		# END handle intermeditate items
		
	def __eq__(self, other):
		"""Compare with another submodule"""
		# we may only compare by name as this should be the ID they are hashed with
		# Otherwise this type wouldn't be hashable
		# return self.path == other.path and self.url == other.url and super(Submodule, self).__eq__(other)
		return self._name == other._name
		
	def __ne__(self, other):
		"""Compare with another submodule for inequality"""
		return not (self == other)
		
	def __hash__(self):
		"""Hash this instance using its logical id, not the sha"""
		return hash(self._name)
		
	def __str__(self):
		return self._name
		
	def __repr__(self):
		return "git.%s(name=%s, path=%s, url=%s, branch_path=%s)" % (type(self).__name__, self._name, self.path, self.url, self.branch_path) 
		
	@classmethod
	def _config_parser(cls, repo, parent_commit, read_only):
		""":return: Config Parser constrained to our submodule in read or write mode
		:raise IOError: If the .gitmodules file cannot be found, either locally or in the repository
			at the given parent commit. Otherwise the exception would be delayed until the first 
			access of the config parser"""
		parent_matches_head = repo.head.commit == parent_commit
		if not repo.bare and parent_matches_head:
			fp_module = cls.k_modules_file
			fp_module_path = os.path.join(repo.working_tree_dir, fp_module)
			if not os.path.isfile(fp_module_path):
				raise IOError("%s file was not accessible" % fp_module_path)
			# END handle existance
			fp_module = fp_module_path
		else:
			try:
				fp_module = cls._sio_modules(parent_commit)
			except KeyError:
				raise IOError("Could not find %s file in the tree of parent commit %s" % (cls.k_modules_file, parent_commit))
			# END handle exceptions
		# END handle non-bare working tree
		
		if not read_only and (repo.bare or not parent_matches_head):
			raise ValueError("Cannot write blobs of 'historical' submodule configurations")
		# END handle writes of historical submodules
		
		return SubmoduleConfigParser(fp_module, read_only = read_only)

	def _clear_cache(self):
		# clear the possibly changed values
		for name in self._cache_attrs:
			try:
				delattr(self, name)
			except AttributeError:
				pass
			# END try attr deletion
		# END for each name to delete
		
	@classmethod
	def _sio_modules(cls, parent_commit):
		""":return: Configuration file as StringIO - we only access it through the respective blob's data"""
		sio = StringIO(parent_commit.tree[cls.k_modules_file].data_stream.read())
		sio.name = cls.k_modules_file
		return sio
	
	def _config_parser_constrained(self, read_only):
		""":return: Config Parser constrained to our submodule in read or write mode"""
		parser = self._config_parser(self.repo, self._parent_commit, read_only)
		parser.set_submodule(self)
		return SectionConstraint(parser, sm_section(self.name))
		
	#{ Edit Interface
	
	@classmethod
	def add(cls, repo, name, path, url=None, branch=None, no_checkout=False):
		"""Add a new submodule to the given repository. This will alter the index
		as well as the .gitmodules file, but will not create a new commit.
		If the submodule already exists, no matter if the configuration differs
		from the one provided, the existing submodule will be returned.
		
		:param repo: Repository instance which should receive the submodule
		:param name: The name/identifier for the submodule
		:param path: repository-relative or absolute path at which the submodule 
			should be located
			It will be created as required during the repository initialization.
		:param url: git-clone compatible URL, see git-clone reference for more information
			If None, the repository is assumed to exist, and the url of the first
			remote is taken instead. This is useful if you want to make an existing
			repository a submodule of anotherone.
		:param branch: name of branch at which the submodule should (later) be checked out.
			The given branch must exist in the remote repository, and will be checked
			out locally as a tracking branch.
			It will only be written into the configuration if it not None, which is
			when the checked out branch will be the one the remote HEAD pointed to.
			The result you get in these situation is somewhat fuzzy, and it is recommended
			to specify at least 'master' here.
			Examples are 'master' or 'feature/new'
		:param no_checkout: if True, and if the repository has to be cloned manually, 
			no checkout will be performed
		:return: The newly created submodule instance
		:note: works atomically, such that no change will be done if the repository
			update fails for instance"""
		if repo.bare:
			raise InvalidGitRepositoryError("Cannot add submodules to bare repositories")
		# END handle bare repos
		
		path = to_native_path_linux(path)
		if path.endswith('/'):
			path = path[:-1]
		# END handle trailing slash
		
		# assure we never put backslashes into the url, as some operating systems 
		# like it ... 
		if url != None:
			url = to_native_path_linux(url)
		#END assure url correctness
		
		# INSTANTIATE INTERMEDIATE SM
		sm = cls(repo, cls.NULL_BIN_SHA, cls.k_default_mode, path, name)
		if sm.exists():
			# reretrieve submodule from tree
			try:
				return repo.head.commit.tree[path]
			except KeyError:
				# could only be in index
				index = repo.index
				entry = index.entries[index.entry_key(path, 0)]
				sm.binsha = entry.binsha
				return sm
			# END handle exceptions
		# END handle existing
		
		# fake-repo - we only need the functionality on the branch instance
		br = git.Head(repo, git.Head.to_full_path(str(branch) or cls.k_head_default))
		has_module = sm.module_exists()
		branch_is_default = branch is None
		if has_module and url is not None:
			if url not in [r.url for r in sm.module().remotes]:
				raise ValueError("Specified URL '%s' does not match any remote url of the repository at '%s'" % (url, sm.abspath))
			# END check url
		# END verify urls match
		
		mrepo = None
		if url is None:
			if not has_module:
				raise ValueError("A URL was not given and existing repository did not exsit at %s" % path)
			# END check url
			mrepo = sm.module()
			urls = [r.url for r in mrepo.remotes]
			if not urls:
				raise ValueError("Didn't find any remote url in repository at %s" % sm.abspath)
			# END verify we have url
			url = urls[0]
		else:
			# clone new repo
			kwargs = {'n' : no_checkout}
			if not branch_is_default:
				kwargs['b'] = br.name
			# END setup checkout-branch
			mrepo = git.Repo.clone_from(url, path, **kwargs)
		# END verify url
		
		# update configuration and index
		index = sm.repo.index
		writer = sm.config_writer(index=index, write=False)
		writer.set_value('url', url)
		writer.set_value('path', path)
		
		sm._url = url
		if not branch_is_default:
			# store full path
			writer.set_value(cls.k_head_option, br.path)
			sm._branch_path = br.path
		# END handle path
		del(writer)
		
		# we deliberatly assume that our head matches our index !
		pcommit = repo.head.commit
		sm._parent_commit = pcommit
		sm.binsha = mrepo.head.commit.binsha
		index.add([sm], write=True)
		
		return sm
		
	def update(self, recursive=False, init=True, to_latest_revision=False, progress=None, 
				dry_run=False):
		"""Update the repository of this submodule to point to the checkout
		we point at with the binsha of this instance.
		
		:param recursive: if True, we will operate recursively and update child-
			modules as well.
		:param init: if True, the module repository will be cloned into place if necessary
		:param to_latest_revision: if True, the submodule's sha will be ignored during checkout.
			Instead, the remote will be fetched, and the local tracking branch updated.
			This only works if we have a local tracking branch, which is the case
			if the remote repository had a master branch, or of the 'branch' option 
			was specified for this submodule and the branch existed remotely
		:param progress: UpdateProgress instance or None of no progress should be shown
		:param dry_run: if True, the operation will only be simulated, but not performed.
			All performed operations are read-only
		:note: does nothing in bare repositories
		:note: method is definitely not atomic if recurisve is True
		:return: self"""
		if self.repo.bare:
			return self
		#END pass in bare mode
		
		if progress is None:
			progress = UpdateProgress()
		#END handle progress
		prefix = ''
		if dry_run:
			prefix = "DRY-RUN: "
		#END handle prefix
		
		# to keep things plausible in dry-run mode
		if dry_run:
			mrepo = None
		#END init mrepo
		
		# ASSURE REPO IS PRESENT AND UPTODATE
		#####################################
		try:
			mrepo = self.module()
			rmts = mrepo.remotes
			len_rmts = len(rmts)
			for i, remote in enumerate(rmts):
				op = FETCH
				if i == 0:
					op |= BEGIN
				#END handle start
				
				progress.update(op, i, len_rmts, prefix+"Fetching remote %s of submodule %r" % (remote, self.name))
				#===============================
				if not dry_run:
					remote.fetch(progress=progress)
				#END handle dry-run
				#===============================
				if i == len_rmts-1:
					op |= END
				#END handle end
				progress.update(op, i, len_rmts, prefix+"Done fetching remote of submodule %r" % self.name)
			#END fetch new data
		except InvalidGitRepositoryError:
			if not init:
				return self
			# END early abort if init is not allowed
			import git
			
			# there is no git-repository yet - but delete empty paths
			module_path = join_path_native(self.repo.working_tree_dir, self.path)
			if not dry_run and os.path.isdir(module_path):
				try:
					os.rmdir(module_path)
				except OSError:
					raise OSError("Module directory at %r does already exist and is non-empty" % module_path)
				# END handle OSError
			# END handle directory removal
			
			# don't check it out at first - nonetheless it will create a local
			# branch according to the remote-HEAD if possible
			progress.update(BEGIN|CLONE, 0, 1, prefix+"Cloning %s to %s in submodule %r" % (self.url, module_path, self.name))
			if not dry_run:
				mrepo = git.Repo.clone_from(self.url, module_path, n=True)
			#END handle dry-run
			progress.update(END|CLONE, 0, 1, prefix+"Done cloning to %s" % module_path)
			
			
			if not dry_run:
				# see whether we have a valid branch to checkout
				try:
					# find  a remote which has our branch - we try to be flexible
					remote_branch = find_first_remote_branch(mrepo.remotes, self.branch_name)
					local_branch = mkhead(mrepo, self.branch_path)
					
					# have a valid branch, but no checkout - make sure we can figure
					# that out by marking the commit with a null_sha
					local_branch.set_object(util.Object(mrepo, self.NULL_BIN_SHA))
					# END initial checkout + branch creation
					
					# make sure HEAD is not detached
					mrepo.head.set_reference(local_branch, logmsg="submodule: attaching head to %s" % local_branch)
					mrepo.head.ref.set_tracking_branch(remote_branch)
				except IndexError:
					print >> sys.stderr, "Warning: Failed to checkout tracking branch %s" % self.branch_path 
				#END handle tracking branch
				
				# NOTE: Have to write the repo config file as well, otherwise
				# the default implementation will be offended and not update the repository
				# Maybe this is a good way to assure it doesn't get into our way, but 
				# we want to stay backwards compatible too ... . Its so redundant !
				self.repo.config_writer().set_value(sm_section(self.name), 'url', self.url)
			#END handle dry_run
		#END handle initalization
		
		
		# DETERMINE SHAS TO CHECKOUT
		############################
		binsha = self.binsha
		hexsha = self.hexsha
		if mrepo is not None:
			# mrepo is only set if we are not in dry-run mode or if the module existed
			is_detached = mrepo.head.is_detached
		#END handle dry_run
		
		if mrepo is not None and to_latest_revision:
			msg_base = "Cannot update to latest revision in repository at %r as " % mrepo.working_dir
			if not is_detached:
				rref = mrepo.head.ref.tracking_branch()
				if rref is not None:
					rcommit = rref.commit
					binsha = rcommit.binsha
					hexsha = rcommit.hexsha
				else:
					print >> sys.stderr, "%s a tracking branch was not set for local branch '%s'" % (msg_base, mrepo.head.ref) 
				# END handle remote ref
			else:
				print >> sys.stderr, "%s there was no local tracking branch" % msg_base
			# END handle detached head
		# END handle to_latest_revision option
		
		# update the working tree
		# handles dry_run
		if mrepo is not None and mrepo.head.commit.binsha != binsha:
			progress.update(BEGIN|UPDWKTREE, 0, 1, prefix+"Updating working tree at %s for submodule %r to revision %s" % (self.path, self.name, hexsha))
			if not dry_run:
				if is_detached:
					# NOTE: for now we force, the user is no supposed to change detached
					# submodules anyway. Maybe at some point this becomes an option, to 
					# properly handle user modifications - see below for future options
					# regarding rebase and merge.
					mrepo.git.checkout(hexsha, force=True)
				else:
					# TODO: allow to specify a rebase, merge, or reset
					# TODO: Warn if the hexsha forces the tracking branch off the remote
					# branch - this should be prevented when setting the branch option
					mrepo.head.reset(hexsha, index=True, working_tree=True)
				# END handle checkout
			#END handle dry_run
			progress.update(END|UPDWKTREE, 0, 1, prefix+"Done updating working tree for submodule %r" % self.name)
		# END update to new commit only if needed
		
		# HANDLE RECURSION
		##################
		if recursive:
			# in dry_run mode, the module might not exist
			if mrepo is not None:
				for submodule in self.iter_items(self.module()):
					submodule.update(recursive, init, to_latest_revision, progress=progress, dry_run=dry_run)
				# END handle recursive update
			#END handle dry run
		# END for each submodule
			
		return self
		
	@unbare_repo
	def move(self, module_path, configuration=True, module=True):
		"""Move the submodule to a another module path. This involves physically moving
		the repository at our current path, changing the configuration, as well as
		adjusting our index entry accordingly.
		
		:param module_path: the path to which to move our module, given as
			repository-relative path. Intermediate directories will be created
			accordingly. If the path already exists, it must be empty.
			Trailling (back)slashes are removed automatically
		:param configuration: if True, the configuration will be adjusted to let 
			the submodule point to the given path.
		:param module: if True, the repository managed by this submodule
			will be moved, not the configuration. This will effectively 
			leave your repository in an inconsistent state unless the configuration
			and index already point to the target location.
		:return: self
		:raise ValueError: if the module path existed and was not empty, or was a file
		:note: Currently the method is not atomic, and it could leave the repository
			in an inconsistent state if a sub-step fails for some reason
		"""
		if module + configuration < 1:
			raise ValueError("You must specify to move at least the module or the configuration of the submodule")
		#END handle input
		
		module_path = to_native_path_linux(module_path)
		if module_path.endswith('/'):
			module_path = module_path[:-1]
		# END handle trailing slash
		
		# VERIFY DESTINATION
		if module_path == self.path:
			return self
		#END handle no change
		
		dest_path = join_path_native(self.repo.working_tree_dir, module_path)
		if os.path.isfile(dest_path):
			raise ValueError("Cannot move repository onto a file: %s" % dest_path)
		# END handle target files
		
		index = self.repo.index
		tekey = index.entry_key(module_path, 0)
		# if the target item already exists, fail
		if configuration and tekey in index.entries:
			raise ValueError("Index entry for target path did alredy exist")
		#END handle index key already there
		
		# remove existing destination
		if module:
			if os.path.exists(dest_path):
				if len(os.listdir(dest_path)):
					raise ValueError("Destination module directory was not empty")
				#END handle non-emptyness
				
				if os.path.islink(dest_path):
					os.remove(dest_path)
				else:
					os.rmdir(dest_path)
				#END handle link
			else:
				# recreate parent directories
				# NOTE: renames() does that now
				pass
			#END handle existance
		# END handle module
		
		# move the module into place if possible
		cur_path = self.abspath
		renamed_module = False
		if module and os.path.exists(cur_path):
			os.renames(cur_path, dest_path)
			renamed_module = True
		#END move physical module
		
		
		# rename the index entry - have to manipulate the index directly as 
		# git-mv cannot be used on submodules ... yeah
		try:
			if configuration:
				try:
					ekey = index.entry_key(self.path, 0)
					entry = index.entries[ekey]
					del(index.entries[ekey])
					nentry = git.IndexEntry(entry[:3]+(module_path,)+entry[4:])
					index.entries[tekey] = nentry
				except KeyError:
					raise InvalidGitRepositoryError("Submodule's entry at %r did not exist" % (self.path))
				#END handle submodule doesn't exist
				
				# update configuration
				writer = self.config_writer(index=index)		# auto-write
				writer.set_value('path', module_path)
				self.path = module_path
				del(writer)
			# END handle configuration flag
		except Exception:
			if renamed_module:
				os.renames(dest_path, cur_path)
			# END undo module renaming
			raise
		#END handle undo rename
		
		return self
		
	@unbare_repo
	def remove(self, module=True, force=False, configuration=True, dry_run=False):
		"""Remove this submodule from the repository. This will remove our entry
		from the .gitmodules file and the entry in the .git/config file.
		
		:param module: If True, the module we point to will be deleted 
			as well. If the module is currently on a commit which is not part 
			of any branch in the remote, if the currently checked out branch 
			working tree, or untracked files,
			is ahead of its tracking branch,  if you have modifications in the
			In case the removal of the repository fails for these reasons, the 
			submodule status will not have been altered.
			If this submodule has child-modules on its own, these will be deleted
			prior to touching the own module.
		:param force: Enforces the deletion of the module even though it contains 
			modifications. This basically enforces a brute-force file system based
			deletion.
		:param configuration: if True, the submodule is deleted from the configuration, 
			otherwise it isn't. Although this should be enabled most of the times, 
			this flag enables you to safely delete the repository of your submodule.
		:param dry_run: if True, we will not actually do anything, but throw the errors
			we would usually throw
		:return: self
		:note: doesn't work in bare repositories
		:raise InvalidGitRepositoryError: thrown if the repository cannot be deleted
		:raise OSError: if directories or files could not be removed"""
		if not (module + configuration):
			raise ValueError("Need to specify to delete at least the module, or the configuration")
		# END handle params
		
		# DELETE MODULE REPOSITORY
		##########################
		if module and self.module_exists():
			if force:
				# take the fast lane and just delete everything in our module path
				# TODO: If we run into permission problems, we have a highly inconsistent
				# state. Delete the .git folders last, start with the submodules first
				mp = self.abspath
				method = None
				if os.path.islink(mp):
					method = os.remove
				elif os.path.isdir(mp):
					method = rmtree
				elif os.path.exists(mp):
					raise AssertionError("Cannot forcibly delete repository as it was neither a link, nor a directory")
				#END handle brutal deletion
				if not dry_run:
					assert method
					method(mp)
				#END apply deletion method
			else:
				# verify we may delete our module
				mod = self.module()
				if mod.is_dirty(untracked_files=True):
					raise InvalidGitRepositoryError("Cannot delete module at %s with any modifications, unless force is specified" % mod.working_tree_dir)
				# END check for dirt
				
				# figure out whether we have new commits compared to the remotes
				# NOTE: If the user pulled all the time, the remote heads might 
				# not have been updated, so commits coming from the remote look
				# as if they come from us. But we stay strictly read-only and
				# don't fetch beforhand.
				for remote in mod.remotes:
					num_branches_with_new_commits = 0
					rrefs = remote.refs
					for rref in rrefs:
						num_branches_with_new_commits = len(mod.git.cherry(rref)) != 0
					# END for each remote ref
					# not a single remote branch contained all our commits
					if num_branches_with_new_commits == len(rrefs):
						raise InvalidGitRepositoryError("Cannot delete module at %s as there are new commits" % mod.working_tree_dir)
					# END handle new commits
					# have to manually delete references as python's scoping is 
					# not existing, they could keep handles open ( on windows this is a problem )
					if len(rrefs):
						del(rref)
					#END handle remotes
					del(rrefs)
					del(remote)
				# END for each remote
				
				# gently remove all submodule repositories
				for sm in self.children():
					sm.remove(module=True, force=False, configuration=False, dry_run=dry_run)
					del(sm)
				# END for each child-submodule
				
				# finally delete our own submodule
				if not dry_run:
					wtd = mod.working_tree_dir
					del(mod)		# release file-handles (windows)
					rmtree(wtd)
				# END delete tree if possible
			# END handle force
		# END handle module deletion
			
		# DELETE CONFIGURATION
		######################
		if configuration and not dry_run:
			# first the index-entry
			index = self.repo.index
			try:
				del(index.entries[index.entry_key(self.path, 0)])
			except KeyError:
				pass
			#END delete entry
			index.write()
			
			# now git config - need the config intact, otherwise we can't query 
			# inforamtion anymore
			self.repo.config_writer().remove_section(sm_section(self.name))
			self.config_writer().remove_section()
		# END delete configuration

		# void our data not to delay invalid access
		self._clear_cache()
		
		return self
		
	def set_parent_commit(self, commit, check=True):
		"""Set this instance to use the given commit whose tree is supposed to 
		contain the .gitmodules blob.
		
		:param commit: Commit'ish reference pointing at the root_tree
		:param check: if True, relatively expensive checks will be performed to verify
			validity of the submodule.
		:raise ValueError: if the commit's tree didn't contain the .gitmodules blob.
		:raise ValueError: if the parent commit didn't store this submodule under the
			current path
		:return: self"""
		pcommit = self.repo.commit(commit)
		pctree = pcommit.tree
		if self.k_modules_file not in pctree:
			raise ValueError("Tree of commit %s did not contain the %s file" % (commit, self.k_modules_file))
		# END handle exceptions
		
		prev_pc = self._parent_commit
		self._parent_commit = pcommit
		
		if check:
			parser = self._config_parser(self.repo, self._parent_commit, read_only=True)
			if not parser.has_section(sm_section(self.name)):
				self._parent_commit = prev_pc
				raise ValueError("Submodule at path %r did not exist in parent commit %s" % (self.path, commit)) 
			# END handle submodule did not exist
		# END handle checking mode
		
		# update our sha, it could have changed
		self.binsha = pctree[self.path].binsha
		
		self._clear_cache()
		
		return self
		
	@unbare_repo
	def config_writer(self, index=None, write=True):
		""":return: a config writer instance allowing you to read and write the data
		belonging to this submodule into the .gitmodules file.
		
		:param index: if not None, an IndexFile instance which should be written.
			defaults to the index of the Submodule's parent repository.
		:param write: if True, the index will be written each time a configuration
			value changes.
		:note: the parameters allow for a more efficient writing of the index, 
			as you can pass in a modified index on your own, prevent automatic writing, 
			and write yourself once the whole operation is complete
		:raise ValueError: if trying to get a writer on a parent_commit which does not
			match the current head commit
		:raise IOError: If the .gitmodules file/blob could not be read"""
		writer = self._config_parser_constrained(read_only=False)
		if index is not None:
			writer.config._index = index
		writer.config._auto_write = write
		return writer
		
	#} END edit interface
	
	#{ Query Interface
	
	@unbare_repo
	def module(self):
		""":return: Repo instance initialized from the repository at our submodule path
		:raise InvalidGitRepositoryError: if a repository was not available. This could 
			also mean that it was not yet initialized"""
		# late import to workaround circular dependencies
		module_path = self.abspath 
		try:
			repo = git.Repo(module_path)
			if repo != self.repo:
				return repo
			# END handle repo uninitialized
		except (InvalidGitRepositoryError, NoSuchPathError):
			raise InvalidGitRepositoryError("No valid repository at %s" % self.path)
		else:
			raise InvalidGitRepositoryError("Repository at %r was not yet checked out" % module_path)
		# END handle exceptions
		
	def module_exists(self):
		""":return: True if our module exists and is a valid git repository. See module() method"""
		try:
			self.module()
			return True
		except Exception:
			return False
		# END handle exception
	
	def exists(self):
		"""
		:return: True if the submodule exists, False otherwise. Please note that
			a submodule may exist (in the .gitmodules file) even though its module
			doesn't exist"""
		# keep attributes for later, and restore them if we have no valid data
		# this way we do not actually alter the state of the object
		loc = locals()
		for attr in self._cache_attrs:
			if hasattr(self, attr):
				loc[attr] = getattr(self, attr)
			# END if we have the attribute cache
		#END for each attr
		self._clear_cache()
		
		try:
			try:
				self.path
				return True
			except Exception:
				return False
			# END handle exceptions
		finally:
			for attr in self._cache_attrs:
				if attr in loc:
					setattr(self, attr, loc[attr])
				# END if we have a cache
			# END reapply each attribute
		# END handle object state consistency
	
	@property
	def branch(self):
		""":return: The branch instance that we are to checkout
		:raise InvalidGitRepositoryError: if our module is not yet checked out"""
		return mkhead(self.module(), self._branch_path)
	
	@property
	def branch_path(self):
		"""
		:return: full (relative) path as string to the branch we would checkout
			from the remote and track"""
		return self._branch_path
		
	@property
	def branch_name(self):
		""":return: the name of the branch, which is the shortest possible branch name"""
		# use an instance method, for this we create a temporary Head instance
		# which uses a repository that is available at least ( it makes no difference )
		return git.Head(self.repo, self._branch_path).name
	
	@property
	def url(self):
		""":return: The url to the repository which our module-repository refers to"""
		return self._url
	
	@property
	def parent_commit(self):
		""":return: Commit instance with the tree containing the .gitmodules file
		:note: will always point to the current head's commit if it was not set explicitly"""
		return self._parent_commit
		
	@property
	def name(self):
		""":return: The name of this submodule. It is used to identify it within the 
			.gitmodules file.
		:note: by default, the name is the path at which to find the submodule, but
			in git-python it should be a unique identifier similar to the identifiers
			used for remotes, which allows to change the path of the submodule
			easily
		"""
		return self._name
	
	def config_reader(self):
		"""
		:return: ConfigReader instance which allows you to qurey the configuration values
			of this submodule, as provided by the .gitmodules file
		:note: The config reader will actually read the data directly from the repository
			and thus does not need nor care about your working tree.
		:note: Should be cached by the caller and only kept as long as needed
		:raise IOError: If the .gitmodules file/blob could not be read"""
		return self._config_parser_constrained(read_only=True)
		
	def children(self):
		"""
		:return: IterableList(Submodule, ...) an iterable list of submodules instances
			which are children of this submodule or 0 if the submodule is not checked out"""
		return self._get_intermediate_items(self)
		
	#} END query interface
	
	#{ Iterable Interface
	
	@classmethod
	def iter_items(cls, repo, parent_commit='HEAD'):
		""":return: iterator yielding Submodule instances available in the given repository"""
		pc = repo.commit(parent_commit)			# parent commit instance
		try:
			parser = cls._config_parser(repo, pc, read_only=True)
		except IOError:
			raise StopIteration
		# END handle empty iterator
		
		rt = pc.tree								# root tree
		
		for sms in parser.sections():
			n = sm_name(sms)
			p = parser.get_value(sms, 'path')
			u = parser.get_value(sms, 'url')
			b = cls.k_head_default
			if parser.has_option(sms, cls.k_head_option):
				b = parser.get_value(sms, cls.k_head_option)
			# END handle optional information
			
			# get the binsha
			index = repo.index
			try:
				sm = rt[p]
			except KeyError:
				# try the index, maybe it was just added
				try:
					entry = index.entries[index.entry_key(p, 0)]
					sm = Submodule(repo, entry.binsha, entry.mode, entry.path)
				except KeyError:
					raise InvalidGitRepositoryError("Gitmodule path %r did not exist in revision of parent commit %s" % (p, parent_commit))
				# END handle keyerror
			# END handle critical error
			
			# fill in remaining info - saves time as it doesn't have to be parsed again
			sm._name = n
			sm._parent_commit = pc
			sm._branch_path = git.Head.to_full_path(b)
			sm._url = u
			
			yield sm
		# END for each section
	
	#} END iterable interface

