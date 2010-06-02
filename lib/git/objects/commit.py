# commit.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from git.utils import Iterable
import git.diff as diff
import git.stats as stats
from git.actor import Actor
from tree import Tree
from cStringIO import StringIO
import base
import utils
import time
import os


class Commit(base.Object, Iterable, diff.Diffable, utils.Traversable, utils.Serializable):
	"""
	Wraps a git Commit object.
	
	This class will act lazily on some of its attributes and will query the 
	value on demand only if it involves calling the git binary.
	"""
	
	# ENVIRONMENT VARIABLES
	# read when creating new commits
	env_author_name = "GIT_AUTHOR_NAME"
	env_author_email = "GIT_AUTHOR_EMAIL"
	env_author_date = "GIT_AUTHOR_DATE"
	env_committer_name = "GIT_COMMITTER_NAME"
	env_committer_email = "GIT_COMMITTER_EMAIL"
	env_committer_date = "GIT_COMMITTER_DATE"
	env_email = "EMAIL"
	
	# CONFIGURATION KEYS
	conf_email = 'email'
	conf_name = 'name'
	conf_encoding = 'i18n.commitencoding'
	
	# INVARIANTS
	default_encoding = "UTF-8"
	
	
	# object configuration 
	type = "commit"
	__slots__ = ("tree",
				 "author", "authored_date", "author_tz_offset",
				 "committer", "committed_date", "committer_tz_offset",
				 "message", "parents", "encoding")
	_id_attribute_ = "sha"
	
	def __init__(self, repo, sha, tree=None, author=None, authored_date=None, author_tz_offset=None,
				 committer=None, committed_date=None, committer_tz_offset=None, 
				 message=None,  parents=None, encoding=None):
		"""
		Instantiate a new Commit. All keyword arguments taking None as default will 
		be implicitly set if id names a valid sha. 
		
		The parameter documentation indicates the type of the argument after a colon ':'.

		:param sha: is the sha id of the commit or a ref
		:param parents: tuple( Commit, ... ) 
			is a tuple of commit ids or actual Commits
		:param tree: Tree
			is the corresponding tree id or an actual Tree
		:param author: Actor
			is the author string ( will be implicitly converted into an Actor object )
		:param authored_date: int_seconds_since_epoch
			is the authored DateTime - use time.gmtime() to convert it into a 
			different format
		:param author_tz_offset: int_seconds_west_of_utc
			is the timezone that the authored_date is in
		:param committer: Actor
			is the committer string
		:param committed_date: int_seconds_since_epoch
			is the committed DateTime - use time.gmtime() to convert it into a 
			different format
		:param committer_tz_offset: int_seconds_west_of_utc
			is the timezone that the authored_date is in
		:param message: string
			is the commit message
		:param encoding: string
			encoding of the message, defaults to UTF-8
		:return: git.Commit
		
		:note: Timezone information is in the same format and in the same sign 
			as what time.altzone returns. The sign is inverted compared to git's 
			UTC timezone.
		"""
		super(Commit,self).__init__(repo, sha)
		self._set_self_from_args_(locals())

		if parents is not None:
			cls = type(self)
			self.parents = tuple(cls(repo, p) for p in parents if not isinstance(p, cls))
		# END for each parent to convert
			
		if self.sha and tree is not None:
			self.tree = Tree(repo, tree, path='')
		# END id to tree conversion
		
	@classmethod
	def _get_intermediate_items(cls, commit):
		return commit.parents

	def _set_cache_(self, attr):
		"""
		Called by LazyMixin superclass when the given uninitialized member needs 
		to be set.
		We set all values at once.
		"""
		if attr in Commit.__slots__:
			# read the data in a chunk, its faster - then provide a file wrapper
			hexsha, typename, size, data = self.repo.git.get_object_data(self)
			self._deserialize(StringIO(data))
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
		# yes, it makes a difference whether empty paths are given or not in our case
		# as the empty paths version will ignore merge commits for some reason.
		if paths:
			return len(self.repo.git.rev_list(self.sha, '--', paths, **kwargs).splitlines())
		else:
			return len(self.repo.git.rev_list(self.sha, **kwargs).splitlines())
		

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
		
		args = list()
		if paths:
			args.extend(('--', paths))
		# END if paths

		proc = repo.git.rev_list(rev, args, **options)
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
		if not hasattr(stream,'readline'):
			stream = proc_or_stream.stdout
			
		while True:
			line = stream.readline()
			if not line:
				break
			commit_tokens = line.split()
			id = commit_tokens[1]
			assert commit_tokens[0] == "commit"
			
			yield Commit(repo, id)._deserialize(stream, from_rev_list) 
		# END for each line in stream
		
		
	@classmethod
	def create_from_tree(cls, repo, tree, message, parent_commits=None, head=False):
		"""Commit the given tree, creating a commit object.
		
		:param repo: Repo object the commit should be part of 
		:param tree: Sha of a tree or a tree object to become the tree of the new commit
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
			more information
		"""
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
		default_email = utils.get_user_id()
		default_name = default_email.split('@')[0]
		
		conf_name = cr.get_value('user', cls.conf_name, default_name)
		conf_email = cr.get_value('user', cls.conf_email, default_email)
		
		author_name = env.get(cls.env_author_name, conf_name)
		author_email = env.get(cls.env_author_email, default_email)
		
		committer_name = env.get(cls.env_committer_name, conf_name)
		committer_email = env.get(cls.env_committer_email, conf_email)
		
		# PARSE THE DATES
		unix_time = int(time.time())
		offset = time.altzone
		
		author_date_str = env.get(cls.env_author_date, '')
		if author_date_str:
			author_time, author_offset = utils.parse_date(author_date_str)
		else:
			author_time, author_offset = unix_time, offset
		# END set author time
		
		committer_date_str = env.get(cls.env_committer_date, '')
		if committer_date_str: 
			committer_time, committer_offset = utils.parse_date(committer_date_str)
		else:
			committer_time, committer_offset = unix_time, offset
		# END set committer time
		
		# assume utf8 encoding
		enc_section, enc_option = cls.conf_encoding.split('.')
		conf_encoding = cr.get_value(enc_section, enc_option, cls.default_encoding)
		
		author = Actor(author_name, author_email)
		committer = Actor(committer_name, committer_email)
		
		
		# CREATE NEW COMMIT
		new_commit = cls(repo, cls.NULL_HEX_SHA, tree, 
						author, author_time, author_offset, 
						committer, committer_time, committer_offset,
						message, parent_commits, conf_encoding)
		
		# serialize !
		
		if head:
			try:
				repo.head.commit = new_commit
			except ValueError:
				# head is not yet set to the ref our HEAD points to
				# Happens on first commit
				import git.refs
				master = git.refs.Head.create(repo, repo.head.ref, commit=new_commit)
				repo.head.reference = master
			# END handle empty repositories
		# END advance head handling 
		
		return new_commit
	
		
	def __str__(self):
		""" Convert commit to string which is SHA1 """
		return self.sha

	def __repr__(self):
		return '<git.Commit "%s">' % self.sha

	#{ Serializable Implementation
	
	def _serialize(self, stream):
		# for now, this is very inefficient and in fact shouldn't be used like this
		return super(Commit, self)._serialize(stream)
	
	def _deserialize(self, stream, from_rev_list=False):
		""":param from_rev_list: if true, the stream format is coming from the rev-list command
		Otherwise it is assumed to be a plain data stream from our object"""
		self.tree = Tree(self.repo, stream.readline().split()[1], 0, '')

		self.parents = list()
		next_line = None
		while True:
			parent_line = stream.readline()
			if not parent_line.startswith('parent'):
				next_line = parent_line
				break
			# END abort reading parents
			self.parents.append(type(self)(self.repo, parent_line.split()[-1]))
		# END for each parent line
		self.parents = tuple(self.parents)
		
		self.author, self.authored_date, self.author_tz_offset = utils.parse_actor_and_date(next_line)
		self.committer, self.committed_date, self.committer_tz_offset = utils.parse_actor_and_date(stream.readline())
		
		
		# empty line
		self.encoding = self.default_encoding
		enc = stream.readline()
		enc.strip()
		if enc:
			self.encoding = enc[enc.find(' ')+1:]
		# END parse encoding
		
		message_lines = list()
		if from_rev_list:
			while True:
				msg_line = stream.readline()
				if not msg_line.startswith('    '):
					# and forget about this empty marker
					# cut the last newline to get rid of the artificial newline added
					# by rev-list command. Lets hope its just linux style \n
					message_lines[-1] = message_lines[-1][:-1]
					break
				# END abort message reading 
				# strip leading 4 spaces
				message_lines.append(msg_line[4:])
			# END while there are message lines
			self.message = ''.join(message_lines)
		else:
			# a stream from our data simply gives us the plain message
			# The end of our message stream is marked with a newline that we strip
			self.message = stream.read()[:-1]
		# END message parsing
		return self
		
	#} END serializable implementation
