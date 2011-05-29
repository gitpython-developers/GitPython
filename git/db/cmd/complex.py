"""Module with our own git implementation - it uses the git command"""
from git.exc import (
					GitCommandError, 
					BadObject
					)

from git.base import (
								OInfo,
								OStream
							)

from git.util import (
							bin_to_hex, 
							hex_to_bin
						)
from git.db.py.loose import PureLooseObjectODB
from git.db.compat import RepoCompatInterface
from git.util import RemoteProgress
from git.db.py.base import (
							TransportDB,
							PureRepositoryPathsMixin,
							PureAlternatesFileMixin
							)
from git.db.interface import FetchInfo as GitdbFetchInfo
from git.db.interface import PushInfo as GitdbPushInfo

from git.util import  join_path
from git.util import join

from git.refs import (
						Reference,
						RemoteReference,
						SymbolicReference, 
						TagReference
					)

import re
import sys


__all__ = ('CmdGitDB', 'RemoteProgress', 'CmdCompatibilityGitDB' )


class PushInfo(GitdbPushInfo):
	"""
	Carries information about the result of a push operation of a single head::
	
		info = remote.push()[0]
		info.flags			# bitflags providing more information about the result
		info.local_ref		# Reference pointing to the local reference that was pushed
							# It is None if the ref was deleted.
		info.remote_ref_string # path to the remote reference located on the remote side
		info.remote_ref # Remote Reference on the local side corresponding to 
						# the remote_ref_string. It can be a TagReference as well.
		info.old_commit_binsha # binary sha at which the remote_ref was standing before we pushed
						# it to local_ref.commit. Will be None if an error was indicated
		info.summary	# summary line providing human readable english text about the push
		"""
	__slots__ = ('local_ref', 'remote_ref_string', 'flags', 'old_commit_binsha', '_remote', 'summary')
	
	_flag_map = {	'X' : GitdbPushInfo.NO_MATCH, 
					'-' : GitdbPushInfo.DELETED, '*' : 0,
					'+' : GitdbPushInfo.FORCED_UPDATE, 
					' ' : GitdbPushInfo.FAST_FORWARD, 
					'=' : GitdbPushInfo.UP_TO_DATE, 
					'!' : GitdbPushInfo.ERROR }
	
	def __init__(self, flags, local_ref, remote_ref_string, remote, old_commit_binsha=None, 
					summary=''):
		""" Initialize a new instance """
		self.flags = flags
		self.local_ref = local_ref
		self.remote_ref_string = remote_ref_string
		self._remote = remote
		self.old_commit_binsha = old_commit_binsha
		self.summary = summary
		
	@property
	def remote_ref(self):
		"""
		:return:
			Remote Reference or TagReference in the local repository corresponding 
			to the remote_ref_string kept in this instance."""
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
		"""Create a new PushInfo instance as parsed from line which is expected to be like
			refs/heads/master:refs/heads/master 05d2687..1d0568e"""
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
		old_commit_binsha = None
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
			# have to use constructor here as the sha usually is abbreviated
			old_commit_binsha = remote.repo.commit(old_sha)
		# END message handling
		
		return PushInfo(flags, from_ref, to_ref_string, remote, old_commit_binsha, summary)
		

class FetchInfo(GitdbFetchInfo):
	"""
	Carries information about the results of a fetch operation of a single head::
	
	 info = remote.fetch()[0]
	 info.ref			# Symbolic Reference or RemoteReference to the changed 
						# remote head or FETCH_HEAD
	 info.flags			# additional flags to be & with enumeration members, 
						# i.e. info.flags & info.REJECTED 
						# is 0 if ref is FETCH_HEAD
	 info.note			# additional notes given by git-fetch intended for the user
	 info.old_commit_binsha	# if info.flags & info.FORCED_UPDATE|info.FAST_FORWARD, 
						# field is set to the previous location of ref, otherwise None
	"""
	__slots__ = ('ref','old_commit_binsha', 'flags', 'note')
	
	#							  %c	%-*s %-*s			  -> %s		  (%s)
	re_fetch_result = re.compile("^\s*(.) (\[?[\w\s\.]+\]?)\s+(.+) -> ([/\w_\+\.-]+)(	 \(.*\)?$)?")
	
	_flag_map = {	'!' : GitdbFetchInfo.ERROR, 
					'+' : GitdbFetchInfo.FORCED_UPDATE, 
					'-' : GitdbFetchInfo.TAG_UPDATE, 
					'*' : 0,
					'=' : GitdbFetchInfo.HEAD_UPTODATE, 
					' ' : GitdbFetchInfo.FAST_FORWARD } 
	
	def __init__(self, ref, flags, note = '', old_commit_binsha = None):
		"""
		Initialize a new instance
		"""
		self.ref = ref
		self.flags = flags
		self.note = note
		self.old_commit_binsha = old_commit_binsha
		
	def __str__(self):
		return self.name
		
	@property
	def name(self):
		""":return: Name of our remote ref"""
		return self.ref.name
		
	@property
	def commit(self):
		""":return: Commit of our remote ref"""
		return self.ref.commit
		
	@classmethod
	def _from_line(cls, repo, line, fetch_line):
		"""Parse information from the given line as returned by git-fetch -v
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
		acb0fa8b94ef421ad60c8507b634759a472cd56c	not-for-merge	branch '0.1.7RC' of /tmp/tmpya0vairemote_repo"""
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
		elif ref_type_name	== "branch":
			ref_type = RemoteReference
		elif ref_type_name == "tag":
			ref_type = TagReference
		else:
			raise TypeError("Cannot handle reference type: %r" % ref_type_name)
			
		# create ref instance
		if ref_type is SymbolicReference:
			remote_local_ref = ref_type(repo, "FETCH_HEAD") 
		else:
			remote_local_ref = Reference.from_path(repo, join_path(ref_type._common_path_default, remote_local_ref.strip()))
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
		old_commit_binsha = None
		if isinstance(remote_local_ref, Reference):
			if 'rejected' in operation:
				flags |= cls.REJECTED
			if 'new tag' in operation:
				flags |= cls.NEW_TAG
			if 'new branch' in operation:
				flags |= cls.NEW_HEAD
			if '...' in operation or '..' in operation:
				split_token = '...'
				if control_character == ' ':
					split_token = split_token[:-1]
				old_commit_binsha = repo.rev_parse(operation.split(split_token)[0])
			# END handle refspec
		# END reference flag handling
		
		return cls(remote_local_ref, flags, note, old_commit_binsha)
		

class CmdGitDB(PureLooseObjectODB, TransportDB, PureRepositoryPathsMixin, PureAlternatesFileMixin):
	"""A database representing the default git object store, which includes loose 
	objects, pack files and an alternates file
	
	It will create objects only in the loose object database.
	:note: for now, we use the git command to do all the lookup, just until he 
		have packs and the other implementations
	"""
	def __init__(self, root_path, git):
		"""Initialize this instance with the root and a git command"""
		self._initialize(root_path)
		super(CmdGitDB, self).__init__(self.objects_dir)
		self._git = git

	@classmethod
	def _digest_process_messages(cls, fh, progress):
		"""Read progress messages from file-like object fh, supplying the respective
		progress messages to the progress instance.
		
		:return: list(line, ...) list of lines without linebreaks that did 
			not contain progress information"""
		line_so_far = ''
		dropped_lines = list()
		while True:
			char = fh.read(1)
			if not char:
				break
			
			if char in ('\r', '\n'):
				dropped_lines.extend(progress._parse_progress_line(line_so_far))
				line_so_far = ''
			else:
				line_so_far += char
			# END process parsed line
		# END while file is not done reading
		return dropped_lines
		
	@classmethod
	def _finalize_proc(cls, proc):
		"""Wait for the process (fetch, pull or push) and handle its errors accordingly"""
		try:
			proc.wait()
		except GitCommandError,e:
			# if a push has rejected items, the command has non-zero return status
			# a return status of 128 indicates a connection error - reraise the previous one
			if proc.poll() == 128:
				raise
			pass
		# END exception handling
		
	
	def _get_fetch_info_from_stderr(self, proc, progress):
		# skip first line as it is some remote info we are not interested in
		output = IterableList('name')
		
		
		# lines which are no progress are fetch info lines
		# this also waits for the command to finish
		# Skip some progress lines that don't provide relevant information
		fetch_info_lines = list()
		for line in self._digest_process_messages(proc.stderr, progress):
			if line.startswith('From') or line.startswith('remote: Total'):
				continue
			elif line.startswith('warning:'):
				print >> sys.stderr, line
				continue
			elif line.startswith('fatal:'):
				raise GitCommandError(("Error when fetching: %s" % line,), 2)
			# END handle special messages
			fetch_info_lines.append(line)
		# END for each line
		
		# read head information 
		fp = open(join(self.root_path(), 'FETCH_HEAD'),'r')
		fetch_head_info = fp.readlines()
		fp.close()
		
		assert len(fetch_info_lines) == len(fetch_head_info)
		
		output.extend(FetchInfo._from_line(self.repo, err_line, fetch_line) 
						for err_line,fetch_line in zip(fetch_info_lines, fetch_head_info))
		
		self._finalize_proc(proc)
		return output
	
	def _get_push_info(self, proc, progress):
		# read progress information from stderr
		# we hope stdout can hold all the data, it should ...
		# read the lines manually as it will use carriage returns between the messages
		# to override the previous one. This is why we read the bytes manually
		self._digest_process_messages(proc.stderr, progress)
		
		output = IterableList('name')
		for line in proc.stdout.readlines():
			try:
				output.append(PushInfo._from_line(self, line))
			except ValueError:
				# if an error happens, additional info is given which we cannot parse
				pass
			# END exception handling 
		# END for each line
		
		self._finalize_proc(proc)
		return output
		
	

	#{ ODB Interface
	# overrides from PureOdb Implementation, which is responsible only for writing
	# objects
	def info(self, sha):
		hexsha, typename, size = self._git.get_object_header(bin_to_hex(sha))
		return OInfo(hex_to_bin(hexsha), typename, size)
		
	def stream(self, sha):
		"""For now, all lookup is done by git itself"""
		hexsha, typename, size, stream = self._git.stream_object_data(bin_to_hex(sha))
		return OStream(hex_to_bin(hexsha), typename, size, stream)
	
	#} END odb interface
	
	# { Interface
	
	def partial_to_complete_sha_hex(self, partial_hexsha):
		""":return: Full binary 20 byte sha from the given partial hexsha
		:raise AmbiguousObjectName:
		:raise BadObject:
		:note: currently we only raise BadObject as git does not communicate 
			AmbiguousObjects separately"""
		try:
			hexsha, typename, size = self._git.get_object_header(partial_hexsha)
			return hex_to_bin(hexsha)
		except (GitCommandError, ValueError):
			raise BadObject(partial_hexsha)
		# END handle exceptions
		
	@property
	def git(self):
		return self._git
	
	#} END interface
	
	#{ Transport DB interface
	
	def push(self, url, refspecs=None, progress=None, **kwargs):
		"""Push given refspecs using the git default implementation
		:param url: may be a remote name or a url
		:param refspecs: single string, RefSpec instance or list of such or None.
		:param progress: RemoteProgress derived instance or None
		:param **kwargs: Additional arguments to be passed to the git-push process"""
		proc = self._git.push(url, refspecs, porcelain=True, as_process=True, **kwargs)
		return self._get_push_info(proc, progress or RemoteProgress())
		
	def pull(self, url, refspecs=None, progress=None, **kwargs):
		"""Fetch and merge the given refspecs. 
		If not refspecs are given, the merge will only work properly if you 
		have setup upstream (tracking) branches.
		:param url: may be a remote name or a url
		:param refspecs: see push()
		:param progress: see push()"""
		proc = self._git.pull(url, refspec, with_extended_output=True, as_process=True, v=True, **kwargs)
		return self._get_fetch_info_from_stderr(proc, progress or RemoteProgress())
		
	def fetch(self, url, refspecs=None, progress=None, **kwargs):
		"""Fetch the latest changes
		:param url: may be a remote name or a url
		:param refspecs: see push()
		:param progress: see push()"""
		proc = self._git.fetch(url, refspec, with_extended_output=True, as_process=True, v=True, **kwargs)
		return self._get_fetch_info_from_stderr(proc, progress or RemoteProgress())
		
	#} end transport db interface
	
	
class CmdCompatibilityGitDB(CmdGitDB, RepoCompatInterface):
	"""Command git database with the compatabilty interface added for 0.3x code"""
