# commit.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from git.util import 		(
							Actor,
							Iterable,
							Stats,
						)
from git.diff import Diffable
from tree import Tree
from gitdb import IStream
from cStringIO import StringIO

import base
from gitdb.util import (
						hex_to_bin
						)
from util import (
						Traversable,
						Serializable,
						parse_date,
						altz_to_utctz_str,
						parse_actor_and_date
					)
from time import (
					time, 
					altzone
				)
import os
import sys

__all__ = ('Commit', )

class Commit(base.Object, Iterable, Diffable, Traversable, Serializable):
	"""Wraps a git Commit object.
	
	This class will act lazily on some of its attributes and will query the 
	value on demand only if it involves calling the git binary."""
	
	# ENVIRONMENT VARIABLES
	# read when creating new commits
	env_author_date = "GIT_AUTHOR_DATE"
	env_committer_date = "GIT_COMMITTER_DATE"
	
	# CONFIGURATION KEYS
	conf_encoding = 'i18n.commitencoding'
	
	# INVARIANTS
	default_encoding = "UTF-8"
	
	
	# object configuration 
	type = "commit"
	__slots__ = ("tree",
				 "author", "authored_date", "author_tz_offset",
				 "committer", "committed_date", "committer_tz_offset",
				 "message", "parents", "encoding")
	_id_attribute_ = "binsha"
	
	def __init__(self, repo, binsha, tree=None, author=None, authored_date=None, author_tz_offset=None,
				 committer=None, committed_date=None, committer_tz_offset=None, 
				 message=None,  parents=None, encoding=None):
		"""Instantiate a new Commit. All keyword arguments taking None as default will 
		be implicitly set on first query. 
		
		:param binsha: 20 byte sha1
		:param parents: tuple( Commit, ... ) 
			is a tuple of commit ids or actual Commits
		:param tree: Tree
			Tree object
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
		:param parents:
			List or tuple of Commit objects which are our parent(s) in the commit 
			dependency graph
		:return: git.Commit
		
		:note: Timezone information is in the same format and in the same sign 
			as what time.altzone returns. The sign is inverted compared to git's 
			UTC timezone."""
		super(Commit,self).__init__(repo, binsha)
		if tree is not None:
			assert isinstance(tree, Tree), "Tree needs to be a Tree instance, was %s" % type(tree)
		if tree is not None:
			self.tree = tree
		if author is not None:
			self.author = author
		if authored_date is not None:
			self.authored_date = authored_date
		if author_tz_offset is not None:
			self.author_tz_offset = author_tz_offset
		if committer is not None:
			self.committer = committer
		if committed_date is not None:
			self.committed_date = committed_date
		if committer_tz_offset is not None:
			self.committer_tz_offset = committer_tz_offset
		if message is not None:
			self.message = message
		if parents is not None:
			self.parents = parents
		if encoding is not None:
			self.encoding = encoding
		
	@classmethod
	def _get_intermediate_items(cls, commit):
		return commit.parents

	def _set_cache_(self, attr):
		if attr in Commit.__slots__:
			# read the data in a chunk, its faster - then provide a file wrapper
			binsha, typename, self.size, stream = self.repo.odb.stream(self.binsha)
			self._deserialize(StringIO(stream.read()))
		else:
			super(Commit, self)._set_cache_(attr)
		# END handle attrs

	@property
	def summary(self):
		""":return: First line of the commit message"""
		return self.message.split('\n', 1)[0]
		
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
	def _iter_from_process_or_stream(cls, repo, proc_or_stream):
		"""Parse out commit information into a list of Commit objects
		We expect one-line per commit, and parse the actual commit information directly
		from our lighting fast object database

		:param proc: git-rev-list process instance - one sha per line
		:return: iterator returning Commit objects"""
		stream = proc_or_stream
		if not hasattr(stream,'readline'):
			stream = proc_or_stream.stdout
			
		readline = stream.readline
		while True:
			line = readline()
			if not line:
				break
			hexsha = line.strip()
			if len(hexsha) > 40:
				# split additional information, as returned by bisect for instance
				hexsha, rest = line.split(None, 1)
			# END handle extra info
			
			assert len(hexsha) == 40, "Invalid line: %s" % hexsha
			yield Commit(repo, hex_to_bin(hexsha))
		# END for each line in stream
		
		
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
	
	#{ Serializable Implementation
	
	def _serialize(self, stream):
		write = stream.write
		write("tree %s\n" % self.tree)
		for p in self.parents:
			write("parent %s\n" % p)
			
		a = self.author
		aname = a.name
		if isinstance(aname, unicode):
			aname = aname.encode(self.encoding)
		# END handle unicode in name
		
		c = self.committer
		fmt = "%s %s <%s> %s %s\n"
		write(fmt % ("author", aname, a.email, 
						self.authored_date, 
						altz_to_utctz_str(self.author_tz_offset)))
			
		# encode committer
		aname = c.name
		if isinstance(aname, unicode):
			aname = aname.encode(self.encoding)
		# END handle unicode in name
		write(fmt % ("committer", aname, c.email, 
						self.committed_date,
						altz_to_utctz_str(self.committer_tz_offset)))
		
		if self.encoding != self.default_encoding:
			write("encoding %s\n" % self.encoding)
		
		write("\n")
		
		# write plain bytes, be sure its encoded according to our encoding
		if isinstance(self.message, unicode):
			write(self.message.encode(self.encoding))
		else:
			write(self.message)
		# END handle encoding
		return self
	
	def _deserialize(self, stream):
		""":param from_rev_list: if true, the stream format is coming from the rev-list command
		Otherwise it is assumed to be a plain data stream from our object"""
		readline = stream.readline
		self.tree = Tree(self.repo, hex_to_bin(readline().split()[1]), Tree.tree_id<<12, '')

		self.parents = list()
		next_line = None
		while True:
			parent_line = readline()
			if not parent_line.startswith('parent'):
				next_line = parent_line
				break
			# END abort reading parents
			self.parents.append(type(self)(self.repo, hex_to_bin(parent_line.split()[-1])))
		# END for each parent line
		self.parents = tuple(self.parents)
		
		self.author, self.authored_date, self.author_tz_offset = parse_actor_and_date(next_line)
		self.committer, self.committed_date, self.committer_tz_offset = parse_actor_and_date(readline())
		
		
		# now we can have the encoding line, or an empty line followed by the optional
		# message.
		self.encoding = self.default_encoding
		# read encoding or empty line to separate message
		enc = readline()
		enc = enc.strip()
		if enc:
			self.encoding = enc[enc.find(' ')+1:]
			# now comes the message separator 
			readline()
		# END handle encoding
		
		# decode the authors name
		try:
			self.author.name = self.author.name.decode(self.encoding) 
		except UnicodeDecodeError:
			print >> sys.stderr, "Failed to decode author name '%s' using encoding %s" % (self.author.name, self.encoding)
		# END handle author's encoding
		
		# decode committer name
		try:
			self.committer.name = self.committer.name.decode(self.encoding) 
		except UnicodeDecodeError:
			print >> sys.stderr, "Failed to decode committer name '%s' using encoding %s" % (self.committer.name, self.encoding)
		# END handle author's encoding
		
		# a stream from our data simply gives us the plain message
		# The end of our message stream is marked with a newline that we strip
		self.message = stream.read()
		try:
			self.message = self.message.decode(self.encoding)
		except UnicodeDecodeError:
			print >> sys.stderr, "Failed to decode message '%s' using encoding %s" % (self.message, self.encoding)
		# END exception handling 
		return self
		
	#} END serializable implementation
