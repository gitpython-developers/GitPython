# repo.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

class AdvancedFunctionalityMixin(object):
	"""An intermediate interface carrying advanced git functionality that can be used
	in other comound repositories which do not implement this functionality themselves.
	
	The mixin must be used with repositories that provide a git command object under
	self.git.
	
	:note: at some point, methods provided here are supposed to be provided by custom interfaces"""
	DAEMON_EXPORT_FILE = 'git-daemon-export-ok'
	
	# precompiled regex
	re_whitespace = re.compile(r'\s+')
	re_hexsha_only = re.compile('^[0-9A-Fa-f]{40}$')
	re_hexsha_shortened = re.compile('^[0-9A-Fa-f]{4,40}$')
	re_author_committer_start = re.compile(r'^(author|committer)')
	re_tab_full_line = re.compile(r'^\t(.*)$')
	
	@property
	def index(self):
		""":return: IndexFile representing this repository's index."""
		return IndexFile(self)

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
	def _clone(cls, git, url, path, odb_default_type, **kwargs):
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
			git.clone(url, path, **kwargs)
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

	def clone(self, path, **kwargs):
		"""Create a clone from this repository.
		:param path:
			is the full path of the new repo (traditionally ends with ./<name>.git).

		:param kwargs:
			odbt = ObjectDatabase Type, allowing to determine the object database
			implementation used by the returned Repo instance
			
			All remaining keyword arguments are given to the git-clone command
			
		:return: ``git.Repo`` (the newly cloned repo)"""
		return self._clone(self.git, self.git_dir, path, type(self.odb), **kwargs)

	@classmethod
	def clone_from(cls, url, to_path, **kwargs):
		"""Create a clone from the given URL
		:param url: valid git url, see http://www.kernel.org/pub/software/scm/git/docs/git-clone.html#URLS
		:param to_path: Path to which the repository should be cloned to
		:param kwargs: see the ``clone`` method
		:return: Repo instance pointing to the cloned directory"""
		return cls._clone(Git(os.getcwd()), url, to_path, CmdGitDB, **kwargs)

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
	
	def rev_parse(self, name):
		return self.odb.resolve(name)
		
	def __repr__(self):
		return '<git.Repo "%s">' % self.git_dir
