# commit.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from git.utils import Iterable
import git.diff as diff
import git.stats as stats
from tree import Tree
import base
import utils

class Commit(base.Object, Iterable, diff.Diffable):
	"""
	Wraps a git Commit object.
	
	This class will act lazily on some of its attributes and will query the 
	value on demand only if it involves calling the git binary.
	"""
	
	# object configuration 
	type = "commit"
	__slots__ = ("tree", "author", "authored_date", "committer", "committed_date",
					"message", "parents")
	_id_attribute_ = "sha"
	
	def __init__(self, repo, sha, tree=None, author=None, authored_date=None,
				 committer=None, committed_date=None, message=None, parents=None):
		"""
		Instantiate a new Commit. All keyword arguments taking None as default will 
		be implicitly set if id names a valid sha. 
		
		The parameter documentation indicates the type of the argument after a colon ':'.

		``sha``
			is the sha id of the commit or a ref

		``parents`` : tuple( Commit, ... )
			is a tuple of commit ids or actual Commits

		``tree`` : Tree
			is the corresponding tree id or an actual Tree

		``author`` : Actor
			is the author string ( will be implicitly converted into an Actor object )

		``authored_date`` : int_seconds_since_epoch
			is the authored DateTime - use time.gmtime() to convert it into a 
			different format

		``committer`` : Actor
			is the committer string

		``committed_date`` : int_seconds_since_epoch
			is the committed DateTime - use time.gmtime() to convert it into a 
			different format

		``message`` : string
			is the commit message

		Returns
			git.Commit
		"""
		super(Commit,self).__init__(repo, sha)
		self._set_self_from_args_(locals())

		if parents is not None:
			self.parents = tuple( self.__class__(repo, p) for p in parents )
		# END for each parent to convert
			
		if self.sha and tree is not None:
			self.tree = Tree(repo, tree, path='')
		# END id to tree conversion

	def _set_cache_(self, attr):
		"""
		Called by LazyMixin superclass when the given uninitialized member needs 
		to be set.
		We set all values at once.
		"""
		if attr in Commit.__slots__:
			# prepare our data lines to match rev-list
			data_lines = self.data.splitlines()
			data_lines.insert(0, "commit %s" % self.sha)
			temp = self._iter_from_process_or_stream(self.repo, iter(data_lines), False).next()
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
		
	def count(self, paths='', **kwargs):
		"""
		Count the number of commits reachable from this commit

		``paths``
			is an optinal path or a list of paths restricting the return value 
			to commits actually containing the paths

		``kwargs``
			Additional options to be passed to git-rev-list. They must not alter
			the ouput style of the command, or parsing will yield incorrect results
		Returns
			int
		"""
		return len(self.repo.git.rev_list(self.sha, '--', paths, **kwargs).strip().splitlines())

	@property
	def name_rev(self):
		"""
		Returns
			String describing the commits hex sha based on the closest Reference.
			Mostly useful for UI purposes
		"""
		return self.repo.git.name_rev(self)

	@classmethod
	def iter_items(cls, repo, rev, paths='', **kwargs):
		"""
		Find all commits matching the given criteria.

		``repo``
			is the Repo

		``rev``
			revision specifier, see git-rev-parse for viable options

		``paths``
			is an optinal path or list of paths, if set only Commits that include the path 
			or paths will be considered

		``kwargs``
			optional keyword arguments to git rev-list where
			``max_count`` is the maximum number of commits to fetch
			``skip`` is the number of commits to skip
			``since`` all commits since i.e. '1970-01-01'

		Returns
			iterator yielding Commit items
		"""
		options = {'pretty': 'raw', 'as_process' : True }
		options.update(kwargs)

		proc = repo.git.rev_list(rev, '--', paths, **options)
		return cls._iter_from_process_or_stream(repo, proc, True)
		
	def iter_parents(self, paths='', **kwargs):
		"""
		Iterate _all_ parents of this commit.
		
		``paths``
			Optional path or list of paths limiting the Commits to those that 
			contain at least one of the paths
		
		``kwargs``
			All arguments allowed by git-rev-list
			
		Return:
			Iterator yielding Commit objects which are parents of self
		"""
		# skip ourselves
		skip = kwargs.get("skip", 1)
		if skip == 0:	# skip ourselves 
			skip = 1
		kwargs['skip'] = skip
		
		return self.iter_items( self.repo, self, paths, **kwargs )

	@property
	def stats(self):
		"""
		Create a git stat from changes between this commit and its first parent 
		or from all changes done if this is the very first commit.
		
		Return
			git.Stats
		"""
		if not self.parents:
			text = self.repo.git.diff_tree(self.sha, '--', numstat=True, root=True)
			text2 = ""
			for line in text.splitlines()[1:]:
				(insertions, deletions, filename) = line.split("\t")
				text2 += "%s\t%s\t%s\n" % (insertions, deletions, filename)
			text = text2
		else:
			text = self.repo.git.diff(self.parents[0].sha, self.sha, '--', numstat=True)
		return stats.Stats._list_from_string(self.repo, text)

	@classmethod
	def _iter_from_process_or_stream(cls, repo, proc_or_stream, from_rev_list):
		"""
		Parse out commit information into a list of Commit objects

		``repo``
			is the Repo

		``proc``
			git-rev-list process instance (raw format)

		``from_rev_list``
			If True, the stream was created by rev-list in which case we parse 
			the message differently
		Returns
			iterator returning Commit objects
		"""
		stream = proc_or_stream
		if not hasattr(stream,'next'):
			stream = proc_or_stream.stdout
			
		for line in stream:
			commit_tokens = line.split() 
			id = commit_tokens[1]
			assert commit_tokens[0] == "commit"
			tree = stream.next().split()[1]

			parents = []
			next_line = None
			for parent_line in stream:
				if not parent_line.startswith('parent'):
					next_line = parent_line
					break
				# END abort reading parents
				parents.append(parent_line.split()[-1])
			# END for each parent line
			
			author, authored_date = utils.parse_actor_and_date(next_line)
			committer, committed_date = utils.parse_actor_and_date(stream.next())
			
			# empty line
			stream.next()
			
			message_lines = []
			if from_rev_list:
				for msg_line in stream:
					if not msg_line.startswith('    '):
						# and forget about this empty marker
						break
					# END abort message reading 
					# strip leading 4 spaces
					message_lines.append(msg_line[4:])
				# END while there are message lines
			else:
				# a stream from our data simply gives us the plain message
				for msg_line in stream:
					message_lines.append(msg_line)
			# END message parsing
			message = '\n'.join(message_lines)
			
			yield Commit(repo, id, parents=tuple(parents), tree=tree, author=author, authored_date=authored_date,
						  committer=committer, committed_date=committed_date, message=message)
		# END for each line in stream
		
		
	def __str__(self):
		""" Convert commit to string which is SHA1 """
		return self.sha

	def __repr__(self):
		return '<git.Commit "%s">' % self.sha

