# repo.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import sys
import re
import gzip
import StringIO

from errors import InvalidGitRepositoryError, NoSuchPathError
from utils import touch, is_git_dir
from cmd import Git
from actor import Actor
from refs import *
from objects import *
from config import GitConfigParser
from remote import Remote

class Repo(object):
	"""
	Represents a git repository and allows you to query references, 
	gather commit information, generate diffs, create and clone repositories query
	the log.
	"""
	DAEMON_EXPORT_FILE = 'git-daemon-export-ok'
	
	# precompiled regex
	re_whitespace = re.compile(r'\s+')
	re_hexsha_only = re.compile('^[0-9A-Fa-f]{40}$')
	re_author_committer_start = re.compile(r'^(author|committer)')
	re_tab_full_line = re.compile(r'^\t(.*)$')
	
	# invariants
	# represents the configuration level of a configuration file
	config_level = ("system", "global", "repository")

	def __init__(self, path=None):
		"""
		Create a new Repo instance

		``path``
			is the path to either the root git directory or the bare git repo

		Examples::

			repo = Repo("/Users/mtrier/Development/git-python")
			repo = Repo("/Users/mtrier/Development/git-python.git")

		Raises
			InvalidGitRepositoryError or NoSuchPathError

		Returns
			``git.Repo``
		"""

		epath = os.path.abspath(os.path.expanduser(path or os.getcwd()))

		if not os.path.exists(epath):
			raise NoSuchPathError(epath)

		self.path = None
		curpath = epath
		while curpath:
			if is_git_dir(curpath):
				self.bare = True
				self.path = curpath
				self.wd = curpath
				break
			gitpath = os.path.join(curpath, '.git')
			if is_git_dir(gitpath):
				self.bare = False
				self.path = gitpath
				self.wd = curpath
				break
			curpath, dummy = os.path.split(curpath)
			if not dummy:
				break

		if self.path is None:
		   raise InvalidGitRepositoryError(epath)

		self.git = Git(self.wd)

	# Description property
	def _get_description(self):
		filename = os.path.join(self.path, 'description')
		return file(filename).read().rstrip()

	def _set_description(self, descr):
		filename = os.path.join(self.path, 'description')
		file(filename, 'w').write(descr+'\n')

	description = property(_get_description, _set_description,
						   doc="the project's description")
	del _get_description
	del _set_description

	@property
	def heads(self):
		"""
		A list of ``Head`` objects representing the branch heads in
		this repo

		Returns
			``git.IterableList(Head, ...)``
		"""
		return Head.list_items(self)

	# alias heads
	branches = heads

	@property
	def head(self,path="HEAD"):
		"""
		Return
			Head Object, reference pointing to commit
			
		``path``
			path to the head or its name, i.e. master or heads/master
		"""
		return Head(self,path)
		
	@property
	def remotes(self):
		"""
		A list of Remote objects allowing to access and manipulate remotes
		
		Returns
			``git.IterableList(Remote, ...)``
		"""
		return Remote.list_items(self)
		
	def remote(self, name='origin'):
		"""
		Return
			Remote with the specified name
		
		Raise 
			ValueError if no remote with such a name exists
		"""
		return Remote(self, name)

	@property
	def tags(self):
		"""
		A list of ``Tag`` objects that are available in this repo

		Returns
			``git.IterableList(TagReference, ...)``
		"""
		return TagReference.list_items(self)
		
	def tag(self,path):
		"""
		Return
			TagReference Object, reference pointing to a Commit or Tag
		
		``path``
			path to the tag reference, i.e. 0.1.5 or tags/0.1.5
		"""
		return TagReference(self, path)
		
	def _get_config_path(self, config_level ):
		# we do not support an absolute path of the gitconfig on windows , 
		# use the global config instead
		if sys.platform == "win32" and config_level == "system":
			config_level = "global"
			
		if config_level == "system":
			return "/etc/gitconfig"
		elif config_level == "global":
			return os.path.expanduser("~/.gitconfig")
		elif config_level == "repository":
			return "%s/config" % self.path
		
		raise ValueError( "Invalid configuration level: %r" % config_level )
			
	@property
	def config_reader(self):
		"""
		Returns
			GitConfigParser allowing to read the full git configuration, but not to write it
			
			The configuration will include values from the system, user and repository 
			configuration files.
			
			NOTE: On windows, system configuration cannot currently be read as the path is 
			unknown, instead the global path will be used.
		"""
		files = [ self._get_config_path(f) for f in self.config_level ]
		return GitConfigParser(files, read_only=True)
		
	def config_writer(self, config_level="repository"):
		"""
		Returns
			GitConfigParser allowing to write values of the specified configuration file level.
			Config writers should be retrieved, used to change the configuration ,and written 
			right away as they will lock the configuration file in question and prevent other's
			to write it.
			
		``config_level``
			One of the following values
			system = sytem wide configuration file
			global = user level configuration file
			repository = configuration file for this repostory only
		"""
		return GitConfigParser(self._get_config_path(config_level), read_only = False)
		
	def commit(self, rev=None):
		"""
		The Commit object for the specified revision

		``rev``
			revision specifier, see git-rev-parse for viable options.
		
		Returns
			``git.Commit``
		"""
		if rev is None:
			rev = self.active_branch
		
		c = Object.new(self, rev)
		assert c.type == "commit", "Revision %s did not point to a commit, but to %s" % (rev, c)
		return c
		
	def iter_trees(self, *args, **kwargs):
		"""
		Returns
			Iterator yielding Tree objects
			
		Note: Takes all arguments known to iter_commits method
		"""
		return ( c.tree for c in self.iter_commits(*args, **kwargs) )

	def tree(self, ref=None):
		"""
		The Tree object for the given treeish reference

		``ref``
			is a Ref instance defaulting to the active_branch if None.

		Examples::

		  repo.tree(repo.heads[0])

		Returns
			``git.Tree``
			
		NOTE
			A ref is requried here to assure you point to a commit or tag. Otherwise
			it is not garantueed that you point to the root-level tree.
			
			If you need a non-root level tree, find it by iterating the root tree. Otherwise
			it cannot know about its path relative to the repository root and subsequent 
			operations might have unexpected results.
		"""
		if ref is None:
			ref = self.active_branch
		if not isinstance(ref, Reference):
			raise ValueError( "Reference required, got %r" % ref )
		
		
		# As we are directly reading object information, we must make sure
		# we truly point to a tree object. We resolve the ref to a sha in all cases
		# to assure the returned tree can be compared properly. Except for
		# heads, ids should always be hexshas
		hexsha, typename, size = self.git.get_object_header( ref )
		if typename != "tree":
			# will raise if this is not a valid tree
			hexsha, typename, size = self.git.get_object_header( str(ref)+'^{tree}' )
		# END tree handling
		ref = hexsha
		
		# the root has an empty relative path and the default mode
		return Tree(self, ref, 0, '')

	def iter_commits(self, rev=None, paths='', **kwargs):
		"""
		A list of Commit objects representing the history of a given ref/commit

		``rev``
			revision specifier, see git-rev-parse for viable options.
			If None, the active branch will be used.

		 ``paths``
			is an optional path or a list of paths to limit the returned commits to
			Commits that do not contain that path or the paths will not be returned.
		
		 ``kwargs``
		 	Arguments to be passed to git-rev-parse - common ones are 
		 	max_count and skip

		Note: to receive only commits between two named revisions, use the 
		"revA..revB" revision specifier

		Returns
			``git.Commit[]``
		"""
		if rev is None:
			rev = self.active_branch
		
		return Commit.iter_items(self, rev, paths, **kwargs)

	def _get_daemon_export(self):
		filename = os.path.join(self.path, self.DAEMON_EXPORT_FILE)
		return os.path.exists(filename)

	def _set_daemon_export(self, value):
		filename = os.path.join(self.path, self.DAEMON_EXPORT_FILE)
		fileexists = os.path.exists(filename)
		if value and not fileexists:
			touch(filename)
		elif not value and fileexists:
			os.unlink(filename)

	daemon_export = property(_get_daemon_export, _set_daemon_export,
							 doc="If True, git-daemon may export this repository")
	del _get_daemon_export
	del _set_daemon_export

	def _get_alternates(self):
		"""
		The list of alternates for this repo from which objects can be retrieved

		Returns
			list of strings being pathnames of alternates
		"""
		alternates_path = os.path.join(self.path, 'objects', 'info', 'alternates')

		if os.path.exists(alternates_path):
			try:
				f = open(alternates_path)
				alts = f.read()
			finally:
				f.close()
			return alts.strip().splitlines()
		else:
			return []

	def _set_alternates(self, alts):
		"""
		Sets the alternates

		``alts``
			is the array of string paths representing the alternates at which 
			git should look for objects, i.e. /home/user/repo/.git/objects

		Raises
			NoSuchPathError
			
		Returns
			None
		"""
		for alt in alts:
			if not os.path.exists(alt):
				raise NoSuchPathError("Could not set alternates. Alternate path %s must exist" % alt)

		if not alts:
			os.remove(os.path.join(self.path, 'objects', 'info', 'alternates'))
		else:
			try:
				f = open(os.path.join(self.path, 'objects', 'info', 'alternates'), 'w')
				f.write("\n".join(alts))
			finally:
				f.close()

	alternates = property(_get_alternates, _set_alternates, doc="Retrieve a list of alternates paths or set a list paths to be used as alternates")

	@property
	def is_dirty(self):
		"""
		Return the status of the index.

		Returns
			``True``, if the index has any uncommitted changes,
			otherwise ``False``

		NOTE
			Working tree changes that have not been staged will not be detected ! 
		"""
		if self.bare:
			# Bare repositories with no associated working directory are
			# always consired to be clean.
			return False

		return len(self.git.diff('HEAD', '--').strip()) > 0
		
	@property
	def untracked_files(self):
		"""
		Returns
			list(str,...)
			
			Files currently untracked as they have not been staged yet. Paths 
			are relative to the current working directory of the git command.
			
		Note
			ignored files will not appear here, i.e. files mentioned in .gitignore
		"""
		# make sure we get all files, no only untracked directores
		proc = self.git.status(untracked_files=True, as_process=True)
		stream = iter(proc.stdout)
		untracked_files = list()
		for line in stream:
			if not line.startswith("# Untracked files:"):
				continue
			# skip two lines
			stream.next()
			stream.next()
			
			for untracked_info in stream:
				if not untracked_info.startswith("#\t"):
					break
				untracked_files.append(untracked_info.replace("#\t", "").rstrip())
			# END for each utracked info line
		# END for each line
		return untracked_files

	@property
	def active_branch(self):
		"""
		The name of the currently active branch.

		Returns
			Head to the active branch
		"""
		return Head( self, self.git.symbolic_ref('HEAD').strip() )
		
			
	def blame(self, rev, file):
		"""
		The blame information for the given file at the given revision.

		``rev``
			revision specifier, see git-rev-parse for viable options.

		Returns
			list: [git.Commit, list: [<line>]]
			A list of tuples associating a Commit object with a list of lines that 
			changed within the given commit. The Commit objects will be given in order
			of appearance.
		"""
		data = self.git.blame(rev, '--', file, p=True)
		commits = {}
		blames = []
		info = None

		for line in data.splitlines(False):
			parts = self.re_whitespace.split(line, 1)
			firstpart = parts[0]
			if self.re_hexsha_only.search(firstpart):
				# handles 
				# 634396b2f541a9f2d58b00be1a07f0c358b999b3 1 1 7		- indicates blame-data start
				# 634396b2f541a9f2d58b00be1a07f0c358b999b3 2 2
				digits = parts[-1].split(" ")
				if len(digits) == 3:
					info = {'id': firstpart}
					blames.append([None, []])
				# END blame data initialization
			else:
				m = self.re_author_committer_start.search(firstpart)
				if m:
					# handles: 
					# author Tom Preston-Werner
					# author-mail <tom@mojombo.com>
					# author-time 1192271832
					# author-tz -0700
					# committer Tom Preston-Werner
					# committer-mail <tom@mojombo.com>
					# committer-time 1192271832
					# committer-tz -0700  - IGNORED BY US
					role = m.group(0)
					if firstpart.endswith('-mail'):
						info["%s_email" % role] = parts[-1]
					elif firstpart.endswith('-time'):
						info["%s_date" % role] = int(parts[-1])
					elif role == firstpart:
						info[role] = parts[-1]
					# END distinguish mail,time,name
				else:
					# handle
					# filename lib/grit.rb
					# summary add Blob
					# <and rest>
					if firstpart.startswith('filename'):
						info['filename'] = parts[-1]
					elif firstpart.startswith('summary'):
						info['summary'] = parts[-1]
					elif firstpart == '':
						if info:
							sha = info['id']
							c = commits.get(sha)
							if c is None:
								c = Commit(  self, id=sha,
											 author=Actor._from_string(info['author'] + ' ' + info['author_email']),
											 authored_date=info['author_date'],
											 committer=Actor._from_string(info['committer'] + ' ' + info['committer_email']),
											 committed_date=info['committer_date'],
											 message=info['summary'])
								commits[sha] = c
							# END if commit objects needs initial creation
							m = self.re_tab_full_line.search(line)
							text,  = m.groups()
							blames[-1][0] = c
							blames[-1][1].append( text )
							info = None
						# END if we collected commit info
					# END distinguish filename,summary,rest
				# END distinguish author|committer vs filename,summary,rest
			# END distinguish hexsha vs other information
		return blames

	@classmethod
	def init(cls, path=None, mkdir=True, **kwargs):
		"""
		Initialize a git repository at the given path if specified

		``path``
			is the full path to the repo (traditionally ends with /<name>.git)
			or None in which case the repository will be created in the current 
			working directory

		``mkdir``
			if specified will create the repository directory if it doesn't
			already exists. Creates the directory with a mode=0755. 
			Only effective if a path is explicitly given

		``kwargs``
			keyword arguments serving as additional options to the git-init command

		Examples::

			git.Repo.init('/var/git/myrepo.git',bare=True)

		Returns
			``git.Repo`` (the newly created repo)
		"""

		if mkdir and path and not os.path.exists(path):
			os.makedirs(path, 0755)

		git = Git(path)
		output = git.init(path, **kwargs)
		return Repo(path)

	def clone(self, path, **kwargs):
		"""
		Create a clone from this repository.

		``path``
			is the full path of the new repo (traditionally ends with /<name>.git)

		``kwargs``
			keyword arguments to be given to the git-clone command

		Returns
			``git.Repo`` (the newly cloned repo)
		"""
		self.git.clone(self.path, path, **kwargs)
		return Repo(path)


	def archive(self, ostream, treeish=None, prefix=None,  **kwargs):
		"""
		Archive the tree at the given revision.
		``ostream``
			file compatible stream object to which the archive will be written

		``treeish``
			is the treeish name/id, defaults to active branch

		``prefix``
			is the optional prefix to prepend to each filename in the archive
			
		``kwargs``
			Additional arguments passed to git-archive
			NOTE: Use the 'format' argument to define the kind of format. Use 
			specialized ostreams to write any format supported by python

		Examples::

			>>> repo.archive(open("archive"
			<String containing tar.gz archive>

			>>> repo.archive_tar_gz('a87ff14')
			<String containing tar.gz archive for commit a87ff14>

			>>> repo.archive_tar_gz('master', 'myproject/')
			<String containing tar.gz archive and prefixed with 'myproject/'>

		Raise
			GitCommandError in case something went wrong
			
		"""
		if treeish is None:
			treeish = self.active_branch
		if prefix and 'prefix' not in kwargs:
			kwargs['prefix'] = prefix
		kwargs['as_process'] = True
		kwargs['output_stream'] = ostream
		
		proc =  self.git.archive(treeish, **kwargs)
		status = proc.wait()
		if status != 0:
			raise GitCommandError( "git-archive", status, proc.stderr.read() )
		


	def __repr__(self):
		return '<git.Repo "%s">' % self.path
