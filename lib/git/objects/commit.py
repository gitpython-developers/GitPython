# commit.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import re
import time

from git.actor import Actor
from tree import Tree
import git.diff as diff
import git.stats as stats
import base

class Commit(base.Object):
	"""
	Wraps a git Commit object.
	
	This class will act lazily on some of its attributes and will query the 
	value on demand only if it involves calling the git binary.
	"""
	# precompiled regex
	re_actor_epoch = re.compile(r'^.+? (.*) (\d+) .*$')
	
	# object configuration 
	type = "commit"
	__slots__ = ("tree", "author", "authored_date", "committer", "committed_date",
					"message", "parents")
	
	def __init__(self, repo, id, tree=None, author=None, authored_date=None,
				 committer=None, committed_date=None, message=None, parents=None):
		"""
		Instantiate a new Commit. All keyword arguments taking None as default will 
		be implicitly set if id names a valid sha. 
		
		The parameter documentation indicates the type of the argument after a colon ':'.

		``id``
			is the sha id of the commit

		``parents`` : tuple( Commit, ... )
			is a tuple of commit ids or actual Commits

		``tree`` : Tree
			is the corresponding tree id or an actual Tree

		``author`` : Actor
			is the author string ( will be implicitly converted into an Actor object )

		``authored_date`` : (tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, tm_wday, tm_yday, tm_isdst )
			is the authored DateTime

		``committer`` : Actor
			is the committer string

		``committed_date`` : (tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, tm_wday, tm_yday, tm_isdst)
			is the committed DateTime

		``message`` : string
			is the commit message

		Returns
			git.Commit
		"""
		super(Commit,self).__init__(repo, id)
		self._set_self_from_args_(locals())

		if parents is not None:
			self.parents = tuple( self.__class__(repo, p) for p in parents )
		# END for each parent to convert
			
		if self.id and tree is not None:
			self.tree = Tree(repo, id=tree)
		# END id to tree conversion

	def _set_cache_(self, attr):
		"""
		Called by LazyMixin superclass when the given uninitialized member needs 
		to be set.
		We set all values at once.
		"""
		if attr in self.__slots__:
			temp = Commit.find_all(self.repo, self.id, max_count=1)[0]
			self.parents = temp.parents
			self.tree = temp.tree
			self.author = temp.author
			self.authored_date = temp.authored_date
			self.committer = temp.committer
			self.committed_date = temp.committed_date
			self.message = temp.message
		else:
			super(Commit, self)._set_cache_(attr)

	@property
	def summary(self):
		"""
		Returns
			First line of the commit message.
		"""
		return self.message.split('\n', 1)[0]

	@classmethod
	def count(cls, repo, ref, path=''):
		"""
		Count the number of commits reachable from this ref

		``repo``
			is the Repo

		``ref``
			is the ref from which to begin (SHA1 or name)

		``path``
			is an optinal path

		Returns
			int
		"""
		return len(repo.git.rev_list(ref, '--', path).strip().splitlines())

	@classmethod
	def find_all(cls, repo, ref, path='', **kwargs):
		"""
		Find all commits matching the given criteria.

		``repo``
			is the Repo

		``ref``
			is the ref from which to begin (SHA1 or name)

		``path``
			is an optinal path, if set only Commits that include the path 
			will be considered

		``kwargs``
			optional keyword arguments to git where
			``max_count`` is the maximum number of commits to fetch
			``skip`` is the number of commits to skip

		Returns
			git.Commit[]
		"""
		options = {'pretty': 'raw'}
		options.update(kwargs)

		output = repo.git.rev_list(ref, '--', path, **options)
		return cls.list_from_string(repo, output)

	@classmethod
	def list_from_string(cls, repo, text):
		"""
		Parse out commit information into a list of Commit objects

		``repo``
			is the Repo

		``text``
			is the text output from the git-rev-list command (raw format)

		Returns
			git.Commit[]
		"""
		lines =text.splitlines(False)
		commits = []

		while lines:
			id = lines.pop(0).split()[1]
			tree = lines.pop(0).split()[1]

			parents = []
			while lines and lines[0].startswith('parent'):
				parents.append(lines.pop(0).split()[-1])
			# END while there are parent lines
			author, authored_date = cls._actor(lines.pop(0))
			committer, committed_date = cls._actor(lines.pop(0))
			
			# free line
			lines.pop(0)
			
			message_lines = []
			while lines and not lines[0].startswith('commit'):
				message_lines.append(lines.pop(0).strip())
			# END while there are message lines
			message = '\n'.join(message_lines[:-1])	# last line is empty

			commits.append(Commit(repo, id=id, parents=parents, tree=tree, author=author, authored_date=authored_date,
								  committer=committer, committed_date=committed_date, message=message))
		# END while lines
		return commits

	@classmethod
	def diff(cls, repo, a, b=None, paths=None):
		"""
		Creates diffs between a tree and the index or between two trees:

		``repo``
			is the Repo

		``a``
			is a named commit

		``b``
			is an optional named commit.  Passing a list assumes you
			wish to omit the second named commit and limit the diff to the
			given paths.

		``paths``
			is a list of paths to limit the diff to.

		Returns
			git.Diff[]::
			
			 between tree and the index if only a is given
			 between two trees if a and b  are given and are commits 
		"""
		paths = paths or []

		if isinstance(b, list):
			paths = b
			b = None

		if paths:
			paths.insert(0, "--")

		if b:
			paths.insert(0, b)
		paths.insert(0, a)
		text = repo.git.diff('-M', full_index=True, *paths)
		return diff.Diff.list_from_string(repo, text)

	@property
	def diffs(self):
		"""
		Returns
			git.Diff[]
			Diffs between this commit and its first parent or all changes if this 
			commit is the first commit and has no parent.
		"""
		if not self.parents:
			d = self.repo.git.show(self.id, '-M', full_index=True, pretty='raw')
			return diff.Diff.list_from_string(self.repo, d)
		else:
			return self.diff(self.repo, self.parents[0].id, self.id)

	@property
	def stats(self):
		"""
		Create a git stat from changes between this commit and its first parent 
		or from all changes done if this is the very first commit.
		
		Return
			git.Stats
		"""
		if not self.parents:
			text = self.repo.git.diff_tree(self.id, '--', numstat=True, root=True)
			text2 = ""
			for line in text.splitlines()[1:]:
				(insertions, deletions, filename) = line.split("\t")
				text2 += "%s\t%s\t%s\n" % (insertions, deletions, filename)
			text = text2
		else:
			text = self.repo.git.diff(self.parents[0].id, self.id, '--', numstat=True)
		return stats.Stats.list_from_string(self.repo, text)

	def __str__(self):
		""" Convert commit to string which is SHA1 """
		return self.id

	def __repr__(self):
		return '<git.Commit "%s">' % self.id

	@classmethod
	def _actor(cls, line):
		"""
		Parse out the actor (author or committer) info

		Returns
			[Actor, gmtime(acted at time)]
		"""
		m = cls.re_actor_epoch.search(line)
		actor, epoch = m.groups()
		return (Actor.from_string(actor), time.gmtime(int(epoch)))
