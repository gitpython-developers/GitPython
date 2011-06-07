# repo.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from git.exc import InvalidGitRepositoryError, NoSuchPathError
from git.cmd import Git
from git.util import Actor
from git.refs import *
from git.index import IndexFile
from git.objects import *
from git.config import GitConfigParser
from git.remote import (
						Remote,
						digest_process_messages,
						finalize_process,
						add_progress
					)

from git.db import (
				GitCmdObjectDB, 
				GitDB
				)

from gitdb.util import (
							join,
							isfile,
							hex_to_bin
						)

from fun import (
					rev_parse,
					is_git_dir,
					touch
				)

import os
import sys
import re

DefaultDBType = GitDB
if sys.version_info[1] < 5:		# python 2.4 compatiblity
	DefaultDBType = GitCmdObjectDB
# END handle python 2.4


__all__ = ('Repo', )


class Repo(object):
	"""Represents a git repository and allows you to query references, 
	gather commit information, generate diffs, create and clone repositories query
	the log.
	
	The following attributes are worth using:
	
	'working_dir' is the working directory of the git command, wich is the working tree 
	directory if available or the .git directory in case of bare repositories
	
	'working_tree_dir' is the working tree directory, but will raise AssertionError
	if we are a bare repository.
	
	'git_dir' is the .git repository directoy, which is always set."""
	DAEMON_EXPORT_FILE = 'git-daemon-export-ok'
	__slots__ = ( "working_dir", "_working_tree_dir", "git_dir", "_bare", "git", "odb" )
	
	# precompiled regex
	re_whitespace = re.compile(r'\s+')
	re_hexsha_only = re.compile('^[0-9A-Fa-f]{40}$')
	re_hexsha_shortened = re.compile('^[0-9A-Fa-f]{4,40}$')
	re_author_committer_start = re.compile(r'^(author|committer)')
	re_tab_full_line = re.compile(r'^\t(.*)$')
	
	# invariants
	# represents the configuration level of a configuration file
	config_level = ("system", "global", "repository")

	def __init__(self, path=None, odbt = DefaultDBType):
		"""Create a new Repo instance

		:param path: is the path to either the root git directory or the bare git repo::

			repo = Repo("/Users/mtrier/Development/git-python")
			repo = Repo("/Users/mtrier/Development/git-python.git")
			repo = Repo("~/Development/git-python.git")
			repo = Repo("$REPOSITORIES/Development/git-python.git")
		
		:param odbt: Object DataBase type - a type which is constructed by providing 
			the directory containing the database objects, i.e. .git/objects. It will
			be used to access all object data
		:raise InvalidGitRepositoryError:
		:raise NoSuchPathError:
		:return: git.Repo """
		epath = os.path.abspath(os.path.expandvars(os.path.expanduser(path or os.getcwd())))

		if not os.path.exists(epath):
			raise NoSuchPathError(epath)

		self.working_dir = None
		self._working_tree_dir = None
		self.git_dir = None
		curpath = epath
		
		# walk up the path to find the .git dir
		while curpath:
			if is_git_dir(curpath):
				self.git_dir = curpath
				self._working_tree_dir = os.path.dirname(curpath)
				break
			gitpath = join(curpath, '.git')
			if is_git_dir(gitpath):
				self.git_dir = gitpath
				self._working_tree_dir = curpath
				break
			curpath, dummy = os.path.split(curpath)
			if not dummy:
				break
		# END while curpath
		
		if self.git_dir is None:
		   raise InvalidGitRepositoryError(epath)

		self._bare = False
		try:
			self._bare = self.config_reader("repository").getboolean('core','bare') 
		except Exception:
			# lets not assume the option exists, although it should
			pass

		# adjust the wd in case we are actually bare - we didn't know that 
		# in the first place
		if self._bare:
			self._working_tree_dir = None
		# END working dir handling
		
		self.working_dir = self._working_tree_dir or self.git_dir
		self.git = Git(self.working_dir)
		
		# special handling, in special times
		args = [join(self.git_dir, 'objects')]
		if issubclass(odbt, GitCmdObjectDB):
			args.append(self.git)
		self.odb = odbt(*args)

	def __eq__(self, rhs):
		if isinstance(rhs, Repo):
			return self.git_dir == rhs.git_dir
		return False
		
	def __ne__(self, rhs):
		return not self.__eq__(rhs)
		
	def __hash__(self):
		return hash(self.git_dir)

	def __repr__(self):
		return "%s(%r)" % (type(self).__name__, self.git_dir)

	# Description property
	def _get_description(self):
		filename = join(self.git_dir, 'description')
		return file(filename).read().rstrip()

	def _set_description(self, descr):
		filename = join(self.git_dir, 'description')
		file(filename, 'w').write(descr+'\n')

	description = property(_get_description, _set_description,
						   doc="the project's description")
	del _get_description
	del _set_description
	
	
	
	@property
	def working_tree_dir(self):
		""":return: The working tree directory of our git repository
		:raise AssertionError: If we are a bare repository"""
		if self._working_tree_dir is None:
			raise AssertionError( "Repository at %r is bare and does not have a working tree directory" % self.git_dir )
		return self._working_tree_dir
	
	@property
	def bare(self):
		""":return: True if the repository is bare"""
		return self._bare

	@property
	def heads(self):
		"""A list of ``Head`` objects representing the branch heads in
		this repo

		:return: ``git.IterableList(Head, ...)``"""
		return Head.list_items(self)
		
	@property
	def references(self):
		"""A list of Reference objects representing tags, heads and remote references.
		
		:return: IterableList(Reference, ...)"""
		return Reference.list_items(self)
		
	# alias for references
	refs = references

	# alias for heads
	branches = heads
	
	@property
	def index(self):
		""":return: IndexFile representing this repository's index."""
		return IndexFile(self)

	@property
	def head(self):
		""":return: HEAD Object pointing to the current head reference"""
		return HEAD(self,'HEAD')
		
	@property
	def remotes(self):
		"""A list of Remote objects allowing to access and manipulate remotes
		:return: ``git.IterableList(Remote, ...)``"""
		return Remote.list_items(self)
		
	def remote(self, name='origin'):
		""":return: Remote with the specified name
		:raise ValueError:  if no remote with such a name exists"""
		return Remote(self, name)
		
	#{ Submodules
		
	@property
	def submodules(self):
		"""
		:return: git.IterableList(Submodule, ...) of direct submodules
			available from the current head"""
		return Submodule.list_items(self)
		
	def submodule(self, name):
		""" :return: Submodule with the given name 
		:raise ValueError: If no such submodule exists"""
		try:
			return self.submodules[name]
		except IndexError:
			raise ValueError("Didn't find submodule named %r" % name)
		# END exception handling
		
	def create_submodule(self, *args, **kwargs):
		"""Create a new submodule
		
		:note: See the documentation of Submodule.add for a description of the 
			applicable parameters
		:return: created submodules"""
		return Submodule.add(self, *args, **kwargs)
		
	def iter_submodules(self, *args, **kwargs):
		"""An iterator yielding Submodule instances, see Traversable interface
		for a description of args and kwargs
		:return: Iterator"""
		return RootModule(self).traverse(*args, **kwargs)
		
	def submodule_update(self, *args, **kwargs):
		"""Update the submodules, keeping the repository consistent as it will 
		take the previous state into consideration. For more information, please
		see the documentation of RootModule.update"""
		return RootModule(self).update(*args, **kwargs)
		
	#}END submodules

	@property
	def tags(self):
		"""A list of ``Tag`` objects that are available in this repo
		:return: ``git.IterableList(TagReference, ...)`` """
		return TagReference.list_items(self)
		
	def tag(self,path):
		""":return: TagReference Object, reference pointing to a Commit or Tag
		:param path: path to the tag reference, i.e. 0.1.5 or tags/0.1.5 """
		return TagReference(self, path)
		
	def create_head(self, path, commit='HEAD', force=False, logmsg=None ):
		"""Create a new head within the repository. 
		For more documentation, please see the Head.create method.
		
		:return: newly created Head Reference"""
		return Head.create(self, path, commit, force, logmsg)
		
	def delete_head(self, *heads, **kwargs):
		"""Delete the given heads
		
		:param kwargs: Additional keyword arguments to be passed to git-branch"""
		return Head.delete(self, *heads, **kwargs)
		
	def create_tag(self, path, ref='HEAD', message=None, force=False, **kwargs):
		"""Create a new tag reference.
		For more documentation, please see the TagReference.create method.
		
		:return: TagReference object """
		return TagReference.create(self, path, ref, message, force, **kwargs)
		
	def delete_tag(self, *tags):
		"""Delete the given tag references"""
		return TagReference.delete(self, *tags)
		
	def create_remote(self, name, url, **kwargs):
		"""Create a new remote.
		
		For more information, please see the documentation of the Remote.create 
		methods 
		
		:return: Remote reference"""
		return Remote.create(self, name, url, **kwargs)
		
	def delete_remote(self, remote):
		"""Delete the given remote."""
		return Remote.remove(self, remote)
		
	def _get_config_path(self, config_level ):
		# we do not support an absolute path of the gitconfig on windows , 
		# use the global config instead
		if sys.platform == "win32" and config_level == "system":
			config_level = "global"
			
		if config_level == "system":
			return "/etc/gitconfig"
		elif config_level == "global":
			return os.path.normpath(os.path.expanduser("~/.gitconfig"))
		elif config_level == "repository":
			return join(self.git_dir, "config")
		
		raise ValueError( "Invalid configuration level: %r" % config_level )
			
	def config_reader(self, config_level=None):
		"""
		:return:
			GitConfigParser allowing to read the full git configuration, but not to write it
			
			The configuration will include values from the system, user and repository 
			configuration files.
			
		:param config_level:
			For possible values, see config_writer method
			If None, all applicable levels will be used. Specify a level in case 
			you know which exact file you whish to read to prevent reading multiple files for 
			instance
		:note: On windows, system configuration cannot currently be read as the path is 
			unknown, instead the global path will be used."""
		files = None
		if config_level is None:
			files = [ self._get_config_path(f) for f in self.config_level ]
		else:
			files = [ self._get_config_path(config_level) ]
		return GitConfigParser(files, read_only=True)
		
	def config_writer(self, config_level="repository"):
		"""
		:return:
			GitConfigParser allowing to write values of the specified configuration file level.
			Config writers should be retrieved, used to change the configuration ,and written 
			right away as they will lock the configuration file in question and prevent other's
			to write it.
			
		:param config_level:
			One of the following values
			system = sytem wide configuration file
			global = user level configuration file
			repository = configuration file for this repostory only"""
		return GitConfigParser(self._get_config_path(config_level), read_only = False)
		
	def commit(self, rev=None):
		"""The Commit object for the specified revision
		:param rev: revision specifier, see git-rev-parse for viable options.
		:return: ``git.Commit``"""
		if rev is None:
			return self.head.commit
		else:
			return self.rev_parse(str(rev)+"^0")
		
	def iter_trees(self, *args, **kwargs):
		""":return: Iterator yielding Tree objects
		:note: Takes all arguments known to iter_commits method"""
		return ( c.tree for c in self.iter_commits(*args, **kwargs) )

	def tree(self, rev=None):
		"""The Tree object for the given treeish revision
		Examples::
	
			  repo.tree(repo.heads[0])

		:param rev: is a revision pointing to a Treeish ( being a commit or tree )
		:return: ``git.Tree``
			
		:note:
			If you need a non-root level tree, find it by iterating the root tree. Otherwise
			it cannot know about its path relative to the repository root and subsequent 
			operations might have unexpected results."""
		if rev is None:
			return self.head.commit.tree
		else:
			return self.rev_parse(str(rev)+"^{tree}")

	def iter_commits(self, rev=None, paths='', **kwargs):
		"""A list of Commit objects representing the history of a given ref/commit

		:parm rev:
			revision specifier, see git-rev-parse for viable options.
			If None, the active branch will be used.

		:parm paths:
			is an optional path or a list of paths to limit the returned commits to
			Commits that do not contain that path or the paths will not be returned.
		
		:parm kwargs:
			Arguments to be passed to git-rev-list - common ones are 
			max_count and skip

		:note: to receive only commits between two named revisions, use the 
			"revA..revB" revision specifier

		:return ``git.Commit[]``"""
		if rev is None:
			rev = self.head.commit
		
		return Commit.iter_items(self, rev, paths, **kwargs)

	def _get_daemon_export(self):
		filename = join(self.git_dir, self.DAEMON_EXPORT_FILE)
		return os.path.exists(filename)

	def _set_daemon_export(self, value):
		filename = join(self.git_dir, self.DAEMON_EXPORT_FILE)
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
		"""The list of alternates for this repo from which objects can be retrieved

		:return: list of strings being pathnames of alternates"""
		alternates_path = join(self.git_dir, 'objects', 'info', 'alternates')

		if os.path.exists(alternates_path):
			try:
				f = open(alternates_path)
				alts = f.read()
			finally:
				f.close()
			return alts.strip().splitlines()
		else:
			return list()

	def _set_alternates(self, alts):
		"""Sets the alternates

		:parm alts:
			is the array of string paths representing the alternates at which 
			git should look for objects, i.e. /home/user/repo/.git/objects

		:raise NoSuchPathError:
		:note:
			The method does not check for the existance of the paths in alts
			as the caller is responsible."""
		alternates_path = join(self.git_dir, 'objects', 'info', 'alternates') 
		if not alts:
			if isfile(alternates_path):
				os.remove(alternates_path)
		else:
			try:
				f = open(alternates_path, 'w')
				f.write("\n".join(alts))
			finally:
				f.close()
			# END file handling 
		# END alts handling

	alternates = property(_get_alternates, _set_alternates, doc="Retrieve a list of alternates paths or set a list paths to be used as alternates")

	def is_dirty(self, index=True, working_tree=True, untracked_files=False):
		"""
		:return:
			``True``, the repository is considered dirty. By default it will react
			like a git-status without untracked files, hence it is dirty if the 
			index or the working copy have changes."""
		if self._bare:
			# Bare repositories with no associated working directory are
			# always consired to be clean.
			return False
		
		# start from the one which is fastest to evaluate
		default_args = ('--abbrev=40', '--full-index', '--raw')
		if index: 
			# diff index against HEAD
			if isfile(self.index.path) and self.head.is_valid() and \
				len(self.git.diff('HEAD', '--cached', *default_args)):
				return True
		# END index handling
		if working_tree:
			# diff index against working tree
			if len(self.git.diff(*default_args)):
				return True
		# END working tree handling
		if untracked_files:
			if len(self.untracked_files):
				return True
		# END untracked files
		return False
		
	@property
	def untracked_files(self):
		"""
		:return:
			list(str,...)
			
			Files currently untracked as they have not been staged yet. Paths 
			are relative to the current working directory of the git command.
			
		:note:
			ignored files will not appear here, i.e. files mentioned in .gitignore"""
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
		"""The name of the currently active branch.

		:return: Head to the active branch"""
		return self.head.reference
			
	def blame(self, rev, file):
		"""The blame information for the given file at the given revision.

		:parm rev: revision specifier, see git-rev-parse for viable options.
		:return:
			list: [git.Commit, list: [<line>]]
			A list of tuples associating a Commit object with a list of lines that 
			changed within the given commit. The Commit objects will be given in order
			of appearance."""
		data = self.git.blame(rev, '--', file, p=True)
		commits = dict()
		blames = list()
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
								c = Commit(	 self, hex_to_bin(sha),
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
		"""Initialize a git repository at the given path if specified

		:param path:
			is the full path to the repo (traditionally ends with /<name>.git)
			or None in which case the repository will be created in the current 
			working directory

		:parm mkdir:
			if specified will create the repository directory if it doesn't
			already exists. Creates the directory with a mode=0755. 
			Only effective if a path is explicitly given

		:parm kwargs:
			keyword arguments serving as additional options to the git-init command

		:return: ``git.Repo`` (the newly created repo)"""

		if mkdir and path and not os.path.exists(path):
			os.makedirs(path, 0755)

		# git command automatically chdir into the directory
		git = Git(path)
		output = git.init(**kwargs)
		return Repo(path)

	@classmethod
	def _clone(cls, git, url, path, odb_default_type, progress, **kwargs):
		# special handling for windows for path at which the clone should be 
		# created.
		# tilde '~' will be expanded to the HOME no matter where the ~ occours. Hence
		# we at least give a proper error instead of letting git fail
		prev_cwd = None
		prev_path = None
		odbt = kwargs.pop('odbt', odb_default_type)
		if os.name == 'nt':
			if '~' in path:
				raise OSError("Git cannot handle the ~ character in path %r correctly" % path)
				
			# on windows, git will think paths like c: are relative and prepend the 
			# current working dir ( before it fails ). We temporarily adjust the working 
			# dir to make this actually work
			match = re.match("(\w:[/\\\])(.*)", path)
			if match:
				prev_cwd = os.getcwd()
				prev_path = path
				drive, rest_of_path = match.groups()
				os.chdir(drive)
				path = rest_of_path
				kwargs['with_keep_cwd'] = True
			# END cwd preparation 
		# END windows handling 
		
		try:
			proc = git.clone(url, path, with_extended_output=True, as_process=True, v=True, **add_progress(kwargs, git, progress))
			if progress:
				digest_process_messages(proc.stderr, progress)
			#END handle progress
			finalize_process(proc)
		finally:
			if prev_cwd is not None:
				os.chdir(prev_cwd)
				path = prev_path
			# END reset previous working dir
		# END bad windows handling
		
		# our git command could have a different working dir than our actual 
		# environment, hence we prepend its working dir if required
		if not os.path.isabs(path) and git.working_dir:
			path = join(git._working_dir, path)
			
		# adjust remotes - there may be operating systems which use backslashes, 
		# These might be given as initial paths, but when handling the config file
		# that contains the remote from which we were clones, git stops liking it
		# as it will escape the backslashes. Hence we undo the escaping just to be 
		# sure
		repo = cls(os.path.abspath(path), odbt = odbt)
		if repo.remotes:
			repo.remotes[0].config_writer.set_value('url', repo.remotes[0].url.replace("\\\\", "\\").replace("\\", "/"))
		# END handle remote repo
		return repo

	def clone(self, path, progress=None, **kwargs):
		"""Create a clone from this repository.
		:param path:
			is the full path of the new repo (traditionally ends with ./<name>.git).

		:param progress: See 'git.remote.Remote.push'.

		:param kwargs:
			odbt = ObjectDatabase Type, allowing to determine the object database
			implementation used by the returned Repo instance
			
			All remaining keyword arguments are given to the git-clone command
			
		:return: ``git.Repo`` (the newly cloned repo)"""
		return self._clone(self.git, self.git_dir, path, type(self.odb), progress, **kwargs)

	@classmethod
	def clone_from(cls, url, to_path, progress=None, **kwargs):
		"""Create a clone from the given URL
		:param url: valid git url, see http://www.kernel.org/pub/software/scm/git/docs/git-clone.html#URLS
		:param to_path: Path to which the repository should be cloned to
		:param progress: See 'git.remote.Remote.push'.
		:param kwargs: see the ``clone`` method
		:return: Repo instance pointing to the cloned directory"""
		return cls._clone(Git(os.getcwd()), url, to_path, GitCmdObjectDB, progress, **kwargs)

	def archive(self, ostream, treeish=None, prefix=None,  **kwargs):
		"""Archive the tree at the given revision.
		:parm ostream: file compatible stream object to which the archive will be written
		:parm treeish: is the treeish name/id, defaults to active branch
		:parm prefix: is the optional prefix to prepend to each filename in the archive
		:parm kwargs:
			Additional arguments passed to git-archive
			NOTE: Use the 'format' argument to define the kind of format. Use 
			specialized ostreams to write any format supported by python

		:raise GitCommandError: in case something went wrong
		:return: self"""
		if treeish is None:
			treeish = self.head.commit
		if prefix and 'prefix' not in kwargs:
			kwargs['prefix'] = prefix 
		kwargs['output_stream'] = ostream
		
		self.git.archive(treeish, **kwargs)
		return self
	
	rev_parse = rev_parse
		
	def __repr__(self):
		return '<git.Repo "%s">' % self.git_dir
