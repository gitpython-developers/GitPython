# remote.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module implementing a remote object allowing easy access to git remotes
"""

from errors import GitCommandError
from git.utils import LazyMixin, Iterable, IterableList
from objects import Commit
from refs import Reference, RemoteReference, SymbolicReference, TagReference

import re
import os

class _SectionConstraint(object):
	"""
	Constrains a ConfigParser to only option commands which are constrained to 
	always use the section we have been initialized with.
	
	It supports all ConfigParser methods that operate on an option
	"""
	__slots__ = ("_config", "_section_name")
	_valid_attrs_ = ("get", "set", "getint", "getfloat", "getboolean", "has_option")
	
	def __init__(self, config, section):
		self._config = config
		self._section_name = section
		
	def __getattr__(self, attr):
		if attr in self._valid_attrs_:
			return lambda *args: self._call_config(attr, *args)
		return super(_SectionConstraint,self).__getattribute__(attr)
		
	def _call_config(self, method, *args):
		"""Call the configuration at the given method which must take a section name 
		as first argument"""
		return getattr(self._config, method)(self._section_name, *args)
		
		
class PushProgress(object):
	"""
	Handler providing an interface to parse progress information emitted by git-push
	and to dispatch callbacks allowing subclasses to react to the progress.
	"""
	BEGIN, END, COUNTING, COMPRESSING, WRITING =  [ 1 << x for x in range(5) ]
	STAGE_MASK = BEGIN|END
	OP_MASK = COUNTING|COMPRESSING|WRITING
	
	__slots__ = ("_cur_line", "_seen_ops")
	re_op_absolute = re.compile("([\w\s]+):\s+()(\d+)()(, done\.)?\s*")
	re_op_relative = re.compile("([\w\s]+):\s+(\d+)% \((\d+)/(\d+)\)(,.* done\.)?$")
	
	def __init__(self):
		self._seen_ops = list()
	
	def _parse_progress_line(self, line):
		"""
		Parse progress information from the given line as retrieved by git-push
		"""
		# handle
		# Counting objects: 4, done. 
		# Compressing objects:  50% (1/2)   \rCompressing objects: 100% (2/2)   \rCompressing objects: 100% (2/2), done.
		self._cur_line = line
		sub_lines = line.split('\r')
		for sline in sub_lines:
			sline = sline.rstrip()
			
			cur_count, max_count = None, None
			match = self.re_op_relative.match(sline)
			if match is None:
				match = self.re_op_absolute.match(sline)
				
			if not match:
				self.line_dropped(sline)
				continue
			# END could not get match
			
			op_code = 0
			op_name, percent, cur_count, max_count, done = match.groups()
			# get operation id
			if op_name == "Counting objects":
				op_code |= self.COUNTING
			elif op_name == "Compressing objects":
				op_code |= self.COMPRESSING
			elif op_name == "Writing objects":
				op_code |= self.WRITING
			else:
				raise ValueError("Operation name %r unknown" % op_name)
			
			# figure out stage
			if op_code not in self._seen_ops:
				self._seen_ops.append(op_code)
				op_code |= self.BEGIN
			# END begin opcode
			
			message = ''
			if done is not None and 'done.' in done:
				op_code |= self.END
				message = done.replace( ", done.", "")[2:]
			# END end flag handling 
			
			self.update(op_code, cur_count, max_count, message)
			
		# END for each sub line
	
	def line_dropped(self, line):
		"""
		Called whenever a line could not be understood and was therefore dropped.
		"""
		pass
	
	def update(self, op_code, cur_count, max_count=None, message=''):
		"""
		Called whenever the progress changes
		
		``op_code``
			Integer allowing to be compared against Operation IDs and stage IDs.
			
			Stage IDs are BEGIN and END. BEGIN will only be set once for each Operation 
			ID as well as END. It may be that BEGIN and END are set at once in case only
			one progress message was emitted due to the speed of the operation.
			Between BEGIN and END, none of these flags will be set
			
			Operation IDs are all held within the OP_MASK. Only one Operation ID will 
			be active per call.
			
		``cur_count``
			Current absolute count of items
			
		``max_count``
			The maximum count of items we expect. It may be None in case there is 
			no maximum number of items or if it is (yet) unknown.
		
		``message``
			In case of the 'WRITING' operation, it contains the amount of bytes
			transferred. It may possibly be used for other purposes as well.
		You may read the contents of the current line in self._cur_line
		"""
		pass
		
		
class PushInfo(object):
	"""
	Carries information about the result of a push operation of a single head::
	 info = remote.push()[0]
	 info.flags			# bitflags providing more information about the result
	 info.local_ref		# Reference pointing to the local reference that was pushed
	 					# It is None if the ref was deleted.
	 info.remote_ref_string # path to the remote reference located on the remote side
	 info.remote_ref	# Remote Reference on the local side corresponding to 
	 					# the remote_ref_string. It can be a TagReference as well.
	 info.old_commit	# commit at which the remote_ref was standing before we pushed
	 					# it to local_ref.commit. Will be None if an error was indicated
	"""
	__slots__ = ('local_ref', 'remote_ref_string', 'flags', 'old_commit', '_remote')
	
	NEW_TAG, NEW_HEAD, NO_MATCH, REJECTED, REMOTE_REJECTED, REMOTE_FAILURE, DELETED, \
	FORCED_UPDATE, FAST_FORWARD, UP_TO_DATE, ERROR = [ 1 << x for x in range(11) ]

	_flag_map = { 	'X' : NO_MATCH, '-' : DELETED, '*' : 0,
					'+' : FORCED_UPDATE, ' ' : FAST_FORWARD, 
					'=' : UP_TO_DATE, '!' : ERROR }
	
	def __init__(self, flags, local_ref, remote_ref_string, remote, old_commit=None):
		"""
		Initialize a new instance
		"""
		self.flags = flags
		self.local_ref = local_ref
		self.remote_ref_string = remote_ref_string
		self._remote = remote
		self.old_commit = old_commit
		
	@property
	def remote_ref(self):
		"""
		Returns
			Remote Reference or TagReference in the local repository corresponding 
			to the remote_ref_string kept in this instance.
		"""
		# translate heads to a local remote, tags stay as they are
		if self.remote_ref_string.startswith("refs/tags"):
			return TagReference(self._remote.repo, self.remote_ref_string)
		elif self.remote_ref_string.startswith("refs/heads"):
			remote_ref = Reference(self._remote.repo, self.remote_ref_string)
			return RemoteReference(self._remote.repo, "refs/remotes/%s/%s" % (str(self._remote), remote_ref.name))
		else:
			raise ValueError("Could not handle remote ref: %r" % self.remote_ref_string)
		# END 
		
	@classmethod
	def _from_line(cls, remote, line):
		"""
		Create a new PushInfo instance as parsed from line which is expected to be like
		c	refs/heads/master:refs/heads/master	05d2687..1d0568e
		"""
		control_character, from_to, summary = line.split('\t', 3)
		flags = 0
		
		# control character handling
		try:
			flags |= cls._flag_map[ control_character ]
		except KeyError:
			raise ValueError("Control Character %r unknown as parsed from line %r" % (control_character, line)) 
		# END handle control character
		
		# from_to handling
		from_ref_string, to_ref_string = from_to.split(':')
		if flags & cls.DELETED:
			from_ref = None
		else:
			from_ref = Reference.from_path(remote.repo, from_ref_string)
		
		# commit handling, could be message or commit info
		old_commit = None
		if summary.startswith('['):
			if "[rejected]" in summary:
				flags |= cls.REJECTED
			elif "[remote rejected]" in summary:
				flags |= cls.REMOTE_REJECTED
			elif "[remote failure]" in summary:
				flags |= cls.REMOTE_FAILURE
			elif "[no match]" in summary:
				flags |= cls.ERROR
			elif "[new tag]" in summary:
				flags |= cls.NEW_TAG
			elif "[new branch]" in summary:
				flags |= cls.NEW_HEAD
			# uptodate encoded in control character
		else:
			# fast-forward or forced update - was encoded in control character, 
			# but we parse the old and new commit
			split_token = "..."
			if control_character == " ":
				split_token = ".."
			old_sha, new_sha = summary.split(' ')[0].split(split_token)
			old_commit = Commit(remote.repo, old_sha)
		# END message handling
		
		return PushInfo(flags, from_ref, to_ref_string, remote, old_commit)
		

class FetchInfo(object):
	"""
	Carries information about the results of a fetch operation of a single head::
	
	 info = remote.fetch()[0]
	 info.ref			# Symbolic Reference or RemoteReference to the changed 
						# remote head or FETCH_HEAD
	 info.flags 		# additional flags to be & with enumeration members, 
						# i.e. info.flags & info.REJECTED 
						# is 0 if ref is SymbolicReference
	 info.note			# additional notes given by git-fetch intended for the user
	 info.commit_before_forced_update	# if info.flags & info.FORCED_UPDATE, 
						# field is set to the previous location of ref, otherwise None
	"""
	__slots__ = ('ref','commit_before_forced_update', 'flags', 'note')
	
	NEW_TAG, NEW_HEAD, HEAD_UPTODATE, TAG_UPDATE, REJECTED, FORCED_UPDATE, \
	FAST_FORWARD, ERROR = [ 1 << x for x in range(8) ]
	
	#                             %c    %-*s %-*s             -> %s       (%s)
	re_fetch_result = re.compile("^\s*(.) (\[?[\w\s\.]+\]?)\s+(.+) -> ([/\w_\.-]+)(  \(.*\)?$)?")
	
	_flag_map = { 	'!' : ERROR, '+' : FORCED_UPDATE, '-' : TAG_UPDATE, '*' : 0,
					'=' : HEAD_UPTODATE, ' ' : FAST_FORWARD } 
	
	def __init__(self, ref, flags, note = '', old_commit = None):
		"""
		Initialize a new instance
		"""
		self.ref = ref
		self.flags = flags
		self.note = note
		self.commit_before_forced_update = old_commit
		
	def __str__(self):
		return self.name
		
	@property
	def name(self):
		"""
		Returns
			Name of our remote ref
		"""
		return self.ref.name
		
	@property
	def commit(self):
		"""
		Returns
			Commit of our remote ref
		"""
		return self.ref.commit
		
	@classmethod
	def _from_line(cls, repo, line, fetch_line):
		"""
		Parse information from the given line as returned by git-fetch -v
		and return a new FetchInfo object representing this information.
		
		We can handle a line as follows
		"%c %-*s %-*s -> %s%s"
		
		Where c is either ' ', !, +, -, *, or =
		! means error
		+ means success forcing update
		- means a tag was updated
		* means birth of new branch or tag
		= means the head was up to date ( and not moved )
		' ' means a fast-forward
		
		fetch line is the corresponding line from FETCH_HEAD, like
		acb0fa8b94ef421ad60c8507b634759a472cd56c	not-for-merge	branch '0.1.7RC' of /tmp/tmpya0vairemote_repo
		"""
		match = cls.re_fetch_result.match(line)
		if match is None:
			raise ValueError("Failed to parse line: %r" % line)
			
		# parse lines
		control_character, operation, local_remote_ref, remote_local_ref, note = match.groups()
		try:
			new_hex_sha, fetch_operation, fetch_note = fetch_line.split("\t")
			ref_type_name, fetch_note = fetch_note.split(' ', 1)
		except ValueError:	# unpack error
			raise ValueError("Failed to parse FETCH__HEAD line: %r" % fetch_line)
		
		# handle FETCH_HEAD and figure out ref type
		# If we do not specify a target branch like master:refs/remotes/origin/master, 
		# the fetch result is stored in FETCH_HEAD which destroys the rule we usually
		# have. In that case we use a symbolic reference which is detached 
		ref_type = None
		if remote_local_ref == "FETCH_HEAD":
			ref_type = SymbolicReference
		elif ref_type_name  == "branch":
			ref_type = RemoteReference
		elif ref_type_name == "tag":
			ref_type = TagReference
		else:
			raise TypeError("Cannot handle reference type: %r" % ref_type_name)
			
		# create ref instance
		if ref_type is SymbolicReference:
			remote_local_ref = ref_type(repo, "FETCH_HEAD") 
		else:
			remote_local_ref = Reference.from_path(repo, os.path.join(ref_type._common_path_default, remote_local_ref.strip()))
		# END create ref instance 
		
		note = ( note and note.strip() ) or ''
		
		# parse flags from control_character
		flags = 0
		try:
			flags |= cls._flag_map[control_character]
		except KeyError:
			raise ValueError("Control character %r unknown as parsed from line %r" % (control_character, line))
		# END control char exception hanlding 
		
		# parse operation string for more info - makes no sense for symbolic refs
		old_commit = None
		if isinstance(remote_local_ref, Reference):
			if 'rejected' in operation:
				flags |= cls.REJECTED
			if 'new tag' in operation:
				flags |= cls.NEW_TAG
			if 'new branch' in operation:
				flags |= cls.NEW_HEAD
			if '...' in operation:
				old_commit = Commit(repo, operation.split('...')[0])
			# END handle refspec
		# END reference flag handling
		
		return cls(remote_local_ref, flags, note, old_commit)
	

class Remote(LazyMixin, Iterable):
	"""
	Provides easy read and write access to a git remote.
	
	Everything not part of this interface is considered an option for the current 
	remote, allowing constructs like remote.pushurl to query the pushurl.
	
	NOTE: When querying configuration, the configuration accessor will be cached
	to speed up subsequent accesses.
	"""
	
	__slots__ = ( "repo", "name", "_config_reader" )
	_id_attribute_ = "name"
	
	def __init__(self, repo, name):
		"""
		Initialize a remote instance
		
		``repo``
			The repository we are a remote of
			
		``name``
			the name of the remote, i.e. 'origin'
		"""
		self.repo = repo
		self.name = name
		
	def __getattr__(self, attr):
		"""
		Allows to call this instance like 
		remote.special( *args, **kwargs) to call git-remote special self.name
		"""
		if attr == "_config_reader":
			return super(Remote, self).__getattr__(attr)
		
		return self._config_reader.get(attr)
	
	def _config_section_name(self):
		return 'remote "%s"' % self.name
	
	def _set_cache_(self, attr):
		if attr == "_config_reader":
			self._config_reader = _SectionConstraint(self.repo.config_reader(), self._config_section_name())
		else:
			super(Remote, self)._set_cache_(attr)
			
	
	def __str__(self):
		return self.name 
	
	def __repr__(self):
		return '<git.%s "%s">' % (self.__class__.__name__, self.name)
		
	def __eq__(self, other):
		return self.name == other.name
		
	def __ne__(self, other):
		return not ( self == other )
		
	def __hash__(self):
		return hash(self.name)
	
	@classmethod
	def iter_items(cls, repo):
		"""
		Returns
			Iterator yielding Remote objects of the given repository
		"""
		seen_remotes = set()
		for name in repo.git.remote().splitlines():
			yield Remote(repo, name)
		# END for each ref
		
	@property
	def refs(self):
		"""
		Returns
			IterableList of RemoteReference objects. It is prefixed, allowing 
			you to omit the remote path portion, i.e.::
			 remote.refs.master # yields RemoteReference('/refs/remotes/origin/master')
		"""
		out_refs = IterableList(RemoteReference._id_attribute_, "%s/" % self.name)
		for ref in RemoteReference.list_items(self.repo):
			if ref.remote_name == self.name:
				out_refs.append(ref)
			# END if names match
		# END for each ref
		assert out_refs, "Remote %s did not have any references" % self.name
		return out_refs
		
	@property
	def stale_refs(self):
		"""
		Returns 
			IterableList RemoteReference objects that do not have a corresponding 
			head in the remote reference anymore as they have been deleted on the 
			remote side, but are still available locally.
			
			The IterableList is prefixed, hence the 'origin' must be omitted. See
			'refs' property for an example.
		"""
		out_refs = IterableList(RemoteReference._id_attribute_, "%s/" % self.name)
		for line in self.repo.git.remote("prune", "--dry-run", self).splitlines()[2:]:
			# expecting 
			# * [would prune] origin/new_branch
			token = " * [would prune] " 
			if not line.startswith(token):
				raise ValueError("Could not parse git-remote prune result: %r" % line)
			fqhn = "%s/%s" % (RemoteReference._common_path_default,line.replace(token, ""))
			out_refs.append(RemoteReference(self.repo, fqhn))
		# END for each line 
		return out_refs
	
	@classmethod
	def create(cls, repo, name, url, **kwargs):
		"""
		Create a new remote to the given repository
		``repo``
			Repository instance that is to receive the new remote
		
		``name``
			Desired name of the remote
		
		``url``
			URL which corresponds to the remote's name
			
		``**kwargs``
			Additional arguments to be passed to the git-remote add command
			
		Returns
			New Remote instance
			
		Raise
			GitCommandError in case an origin with that name already exists
		"""
		repo.git.remote( "add", name, url, **kwargs )
		return cls(repo, name)
	
	# add is an alias
	add = create
	
	@classmethod
	def remove(cls, repo, name ):
		"""
		Remove the remote with the given name
		"""
		repo.git.remote("rm", name)
		
	# alias
	rm = remove
		
	def rename(self, new_name):
		"""
		Rename self to the given new_name
		
		Returns
			self
		"""
		if self.name == new_name:
			return self
		
		self.repo.git.remote("rename", self.name, new_name)
		self.name = new_name
		del(self._config_reader)		# it contains cached values, section names are different now
		return self
		
	def update(self, **kwargs):
		"""
		Fetch all changes for this remote, including new branches which will 
		be forced in ( in case your local remote branch is not part the new remote branches
		ancestry anymore ).
		
		``kwargs``
			Additional arguments passed to git-remote update
		
		Returns
			self
		"""
		self.repo.git.remote("update", self.name)
		return self
	
	def _get_fetch_info_from_stderr(self, stderr):
		# skip first line as it is some remote info we are not interested in
		output = IterableList('name')
		err_info = stderr.splitlines()[1:]
		
		# read head information 
		fp = open(os.path.join(self.repo.path, 'FETCH_HEAD'),'r')
		fetch_head_info = fp.readlines()
		fp.close()
		
		output.extend(FetchInfo._from_line(self.repo, err_line, fetch_line) 
						for err_line,fetch_line in zip(err_info, fetch_head_info))
		return output
	
	def _get_push_info(self, proc, progress):
		# read progress information from stderr
		# we hope stdout can hold all the data, it should ... 
		for line in proc.stderr.readlines():
			progress._parse_progress_line(line.rstrip())
		# END for each progress line
		
		output = IterableList('name')
		for line in proc.stdout.readlines():
			try:
				output.append(PushInfo._from_line(self, line))
			except ValueError:
				# if an error happens, additional info is given which we cannot parse
				pass
			# END exception handling 
		# END for each line
		try:
			proc.wait()
		except GitCommandError:
			# if a push has rejected items, the command has non-zero return status
			pass
		# END exception handling 
		return output
		
	
	def fetch(self, refspec=None, **kwargs):
		"""
		Fetch the latest changes for this remote
		
		``refspec``
			A "refspec" is used by fetch and push to describe the mapping 
			between remote ref and local ref. They are combined with a colon in 
			the format <src>:<dst>, preceded by an optional plus sign, +. 
			For example: git fetch $URL refs/heads/master:refs/heads/origin means 
			"grab the master branch head from the $URL and store it as my origin 
			branch head". And git push $URL refs/heads/master:refs/heads/to-upstream 
			means "publish my master branch head as to-upstream branch at $URL". 
			See also git-push(1).
			
			Taken from the git manual
		
		``**kwargs``
			Additional arguments to be passed to git-fetch
			
		Returns
			IterableList(FetchInfo, ...) list of FetchInfo instances providing detailed 
			information about the fetch results
			
		Note
			As fetch does not provide progress information to non-ttys, we cannot make 
			it available here unfortunately as in the 'push' method.
		"""
		status, stdout, stderr = self.repo.git.fetch(self, refspec, with_extended_output=True, v=True, **kwargs)
		return self._get_fetch_info_from_stderr(stderr)
		
	def pull(self, refspec=None, **kwargs):
		"""
		Pull changes from the given branch, being the same as a fetch followed 
		by a merge of branch with your local branch.
		
		``refspec``
			see 'fetch' method
		
		``**kwargs``
			Additional arguments to be passed to git-pull
			
		Returns
			Please see 'fetch' method
		"""
		status, stdout, stderr = self.repo.git.pull(self, refspec, with_extended_output=True, v=True, **kwargs)
		return self._get_fetch_info_from_stderr(stderr)
		
	def push(self, refspec=None, progress=None, **kwargs):
		"""
		Push changes from source branch in refspec to target branch in refspec.
		
		``refspec``
			see 'fetch' method
		
		``progress``
			Instance of type PushProgress allowing the caller to receive 
			progress information until the method returns.
			If None, progress information will be discarded
		
		``**kwargs``
			Additional arguments to be passed to git-push
			
		Returns
			IterableList(PushInfo, ...) iterable list of PushInfo instances, each 
			one informing about an individual head which had been updated on the remote 
			side.
			If the push contains rejected heads, these will have the PushInfo.ERROR bit set
			in their flags.
			If the operation fails completely, the length of the returned IterableList will
			be null.
		"""
		proc = self.repo.git.push(self, refspec, porcelain=True, as_process=True, **kwargs)
		return self._get_push_info(proc, progress or PushProgress())
		
	@property
	def config_reader(self):
		"""
		Returns
			GitConfigParser compatible object able to read options for only our remote.
			Hence you may simple type config.get("pushurl") to obtain the information
		"""
		return self._config_reader
	
	@property
	def config_writer(self):
		"""
		Return
			GitConfigParser compatible object able to write options for this remote.
			
		Note
			You can only own one writer at a time - delete it to release the 
			configuration file and make it useable by others.
			
			To assure consistent results, you should only query options through the 
			writer. Once you are done writing, you are free to use the config reader 
			once again.
		"""
		writer = self.repo.config_writer()
		
		# clear our cache to assure we re-read the possibly changed configuration
		del(self._config_reader)
		return _SectionConstraint(writer, self._config_section_name())
