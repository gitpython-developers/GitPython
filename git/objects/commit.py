# commit.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.util import RepoAliasMixin
from gitdb.object.commit import Commit as GitDB_Commit
from git.diff import Diffable
from gitdb.util import (
						Iterable,
						Actor
						)

from gitdb import IStream
from cStringIO import StringIO

from util import parse_date
from time import altzone

import os

__all__ = ('Commit', )

class Commit(GitDB_Commit, Diffable, Iterable, RepoAliasMixin):
	"""Provides additional git-command based functionality to the default gitdb commit object"""
	__slots__ = tuple()
	
	def count(self, paths='', **kwargs):
		"""Count the number of commits reachable from this commit

		:param paths:
			is an optinal path or a list of paths restricting the return value 
			to commits actually containing the paths

		:param kwargs:
			Additional options to be passed to git-rev-list. They must not alter
			the ouput style of the command, or parsing will yield incorrect results
		:return: int defining the number of reachable commits"""
		# yes, it makes a difference whether empty paths are given or not in our case
		# as the empty paths version will ignore merge commits for some reason.
		if paths:
			return len(self.repo.git.rev_list(self.hexsha, '--', paths, **kwargs).splitlines())
		else:
			return len(self.repo.git.rev_list(self.hexsha, **kwargs).splitlines())
		

	@property
	def name_rev(self):
		"""
		:return:
			String describing the commits hex sha based on the closest Reference.
			Mostly useful for UI purposes"""
		return self.repo.git.name_rev(self)

	@classmethod
	def iter_items(cls, repo, rev, paths='', **kwargs):
		"""Find all commits matching the given criteria.

		:param repo: is the Repo
		:param rev: revision specifier, see git-rev-parse for viable options
		:param paths:
			is an optinal path or list of paths, if set only Commits that include the path 
			or paths will be considered
		:param kwargs:
			optional keyword arguments to git rev-list where
			``max_count`` is the maximum number of commits to fetch
			``skip`` is the number of commits to skip
			``since`` all commits since i.e. '1970-01-01'
		:return: iterator yielding Commit items"""
		if 'pretty' in kwargs:
			raise ValueError("--pretty cannot be used as parsing expects single sha's only")
		# END handle pretty
		args = list()
		if paths:
			args.extend(('--', paths))
		# END if paths

		proc = repo.git.rev_list(rev, args, as_process=True, **kwargs)
		return cls._iter_from_process_or_stream(repo, proc)
		
	def iter_parents(self, paths='', **kwargs):
		"""Iterate _all_ parents of this commit.
		
		:param paths:
			Optional path or list of paths limiting the Commits to those that 
			contain at least one of the paths
		:param kwargs: All arguments allowed by git-rev-list
		:return: Iterator yielding Commit objects which are parents of self """
		# skip ourselves
		skip = kwargs.get("skip", 1)
		if skip == 0:	# skip ourselves 
			skip = 1
		kwargs['skip'] = skip
		
		return self.iter_items(self.repo, self, paths, **kwargs)

	@property
	def stats(self):
		"""Create a git stat from changes between this commit and its first parent 
		or from all changes done if this is the very first commit.
		
		:return: git.Stats"""
		if not self.parents:
			text = self.repo.git.diff_tree(self.hexsha, '--', numstat=True, root=True)
			text2 = ""
			for line in text.splitlines()[1:]:
				(insertions, deletions, filename) = line.split("\t")
				text2 += "%s\t%s\t%s\n" % (insertions, deletions, filename)
			text = text2
		else:
			text = self.repo.git.diff(self.parents[0].hexsha, self.hexsha, '--', numstat=True)
		return Stats._list_from_string(self.repo, text)

		
	@classmethod
	def create_from_tree(cls, repo, tree, message, parent_commits=None, head=False):
		"""Commit the given tree, creating a commit object.
		
		:param repo: Repo object the commit should be part of 
		:param tree: Tree object or hex or bin sha 
			the tree of the new commit
		:param message: Commit message. It may be an empty string if no message is provided.
			It will be converted to a string in any case.
		:param parent_commits:
			Optional Commit objects to use as parents for the new commit.
			If empty list, the commit will have no parents at all and become 
			a root commit.
			If None , the current head commit will be the parent of the 
			new commit object
		:param head:
			If True, the HEAD will be advanced to the new commit automatically.
			Else the HEAD will remain pointing on the previous commit. This could 
			lead to undesired results when diffing files.
			
		:return: Commit object representing the new commit
			
		:note:
			Additional information about the committer and Author are taken from the
			environment or from the git configuration, see git-commit-tree for 
			more information"""
		parents = parent_commits
		if parent_commits is None:
			try:
				parent_commits = [ repo.head.commit ]
			except ValueError:
				# empty repositories have no head commit
				parent_commits = list()
			# END handle parent commits
		# END if parent commits are unset
		
		# retrieve all additional information, create a commit object, and 
		# serialize it
		# Generally: 
		# * Environment variables override configuration values
		# * Sensible defaults are set according to the git documentation
		
		# COMMITER AND AUTHOR INFO
		cr = repo.config_reader()
		env = os.environ
		
		committer = Actor.committer(cr)
		author = Actor.author(cr)
		
		# PARSE THE DATES
		unix_time = int(time())
		offset = altzone
		
		author_date_str = env.get(cls.env_author_date, '')
		if author_date_str:
			author_time, author_offset = parse_date(author_date_str)
		else:
			author_time, author_offset = unix_time, offset
		# END set author time
		
		committer_date_str = env.get(cls.env_committer_date, '')
		if committer_date_str: 
			committer_time, committer_offset = parse_date(committer_date_str)
		else:
			committer_time, committer_offset = unix_time, offset
		# END set committer time
		
		# assume utf8 encoding
		enc_section, enc_option = cls.conf_encoding.split('.')
		conf_encoding = cr.get_value(enc_section, enc_option, cls.default_encoding)
		
		
		# if the tree is no object, make sure we create one - otherwise
		# the created commit object is invalid
		if isinstance(tree, str):
			tree = repo.tree(tree)
		# END tree conversion
		
		# CREATE NEW COMMIT
		new_commit = cls(repo, cls.NULL_BIN_SHA, tree, 
						author, author_time, author_offset, 
						committer, committer_time, committer_offset,
						message, parent_commits, conf_encoding)
		
		stream = StringIO()
		new_commit._serialize(stream)
		streamlen = stream.tell()
		stream.seek(0)
		
		istream = repo.odb.store(IStream(cls.type, streamlen, stream))
		new_commit.binsha = istream.binsha
		
		if head:
			# need late import here, importing git at the very beginning throws
			# as well ... 
			import git.refs
			try:
				repo.head.set_commit(new_commit, logmsg="commit: %s" % message)
			except ValueError:
				# head is not yet set to the ref our HEAD points to
				# Happens on first commit
				import git.refs
				master = git.refs.Head.create(repo, repo.head.ref, new_commit, logmsg="commit (initial): %s" % message)
				repo.head.set_reference(master, logmsg='commit: Switching to %s' % master)
			# END handle empty repositories
		# END advance head handling 
		
		return new_commit
		
	#} END serializable implementation
