"""module with git command implementations of the basic interfaces
:note: we could add all implementations of the basic interfaces, its more efficient though
 	to obtain them from the pure implementation"""
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
							hex_to_bin,
							isfile,
							join_path,
							join,
							Actor,
							IterableList,
					)
from git.db.interface import (
							FetchInfo,
							PushInfo,
							HighLevelRepository,
							TransportDB,
							RemoteProgress
							)
from git.cmd import Git
from git.refs import (
						Reference,
						RemoteReference,
						SymbolicReference, 
						TagReference
					)
from git.objects.commit import Commit
from cStringIO import StringIO
import re
import os
import sys


__all__ = ('CmdTransportMixin', 'GitCommandMixin', 'CmdPushInfo', 'CmdFetchInfo', 
			'CmdRemoteProgress', 'CmdObjectDBRMixin', 'CmdHighLevelRepository')


#{ Utilities

def touch(filename):
	fp = open(filename, "a")
	fp.close()
	
	
def digest_process_messages(fh, progress):
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
	
def finalize_process(proc):
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
	

def get_fetch_info_from_stderr(repo, proc, progress):
	# skip first line as it is some remote info we are not interested in
	output = IterableList('name')
	
	
	# lines which are no progress are fetch info lines
	# this also waits for the command to finish
	# Skip some progress lines that don't provide relevant information
	fetch_info_lines = list()
	for line in digest_process_messages(proc.stderr, progress):
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
	fp = open(join(repo.git_dir, 'FETCH_HEAD'),'r')
	fetch_head_info = fp.readlines()
	fp.close()
	
	assert len(fetch_info_lines) == len(fetch_head_info)
	
	output.extend(CmdFetchInfo._from_line(repo, err_line, fetch_line) 
					for err_line,fetch_line in zip(fetch_info_lines, fetch_head_info))
	
	finalize_process(proc)
	return output

def get_push_info(repo, remotename_or_url, proc, progress):
	# read progress information from stderr
	# we hope stdout can hold all the data, it should ...
	# read the lines manually as it will use carriage returns between the messages
	# to override the previous one. This is why we read the bytes manually
	digest_process_messages(proc.stderr, progress)
	
	output = IterableList('name')
	for line in proc.stdout.readlines():
		try:
			output.append(CmdPushInfo._from_line(repo, remotename_or_url, line))
		except ValueError:
			# if an error happens, additional info is given which we cannot parse
			pass
		# END exception handling 
	# END for each line
	
	finalize_process(proc)
	return output

def add_progress(kwargs, git, progress):
	"""Add the --progress flag to the given kwargs dict if supported by the 
	git command. If the actual progress in the given progress instance is not 
	given, we do not request any progress
	:return: possibly altered kwargs"""
	if progress._progress is not None:
		v = git.version_info
		if v[0] > 1 or v[1] > 7 or v[2] > 0 or v[3] > 3:
			kwargs['progress'] = True
		#END handle --progress
	#END handle progress
	return kwargs

#} END utilities

class CmdRemoteProgress(RemoteProgress):
	"""
	A Remote progress implementation taking a user derived progress to call the 
	respective methods on.
	"""
	__slots__ = ("_seen_ops", '_progress')
	re_op_absolute = re.compile("(remote: )?([\w\s]+):\s+()(\d+)()(.*)")
	re_op_relative = re.compile("(remote: )?([\w\s]+):\s+(\d+)% \((\d+)/(\d+)\)(.*)")
	
	def __init__(self, progress_instance = None):
		self._seen_ops = list()
		if progress_instance is None:
			progress_instance = RemoteProgress()
		#END assure proper instance
		self._progress = progress_instance
	
	def _parse_progress_line(self, line):
		"""Parse progress information from the given line as retrieved by git-push
		or git-fetch
		
		Call the own update(), __call__() and line_dropped() methods according 
		to the parsed result.
		
		:return: list(line, ...) list of lines that could not be processed"""
		# handle
		# Counting objects: 4, done. 
		# Compressing objects:	50% (1/2)	\rCompressing objects: 100% (2/2)	\rCompressing objects: 100% (2/2), done.
		sub_lines = line.split('\r')
		failed_lines = list()
		for sline in sub_lines:
			# find esacpe characters and cut them away - regex will not work with 
			# them as they are non-ascii. As git might expect a tty, it will send them
			last_valid_index = None
			for i,c in enumerate(reversed(sline)):
				if ord(c) < 32:
					# its a slice index
					last_valid_index = -i-1 
				# END character was non-ascii
			# END for each character in sline
			if last_valid_index is not None:
				sline = sline[:last_valid_index]
			# END cut away invalid part
			sline = sline.rstrip()
			
			cur_count, max_count = None, None
			match = self.re_op_relative.match(sline)
			if match is None:
				match = self.re_op_absolute.match(sline)
				
			if not match:
				self._progress.line_dropped(sline)
				failed_lines.append(sline)
				continue
			# END could not get match
			
			op_code = 0
			remote, op_name, percent, cur_count, max_count, message = match.groups()
			
			# get operation id
			if op_name == "Counting objects":
				op_code |= self.COUNTING
			elif op_name == "Compressing objects":
				op_code |= self.COMPRESSING
			elif op_name == "Writing objects":
				op_code |= self.WRITING
			elif op_name == "Receiving objects":
				op_code |= self.RECEIVING
			elif op_name == "Resolving deltas":
				op_code |= self.RESOLVING
			else:
				# Note: On windows it can happen that partial lines are sent
				# Hence we get something like "CompreReceiving objects", which is 
				# a blend of "Compressing objects" and "Receiving objects".
				# This can't really be prevented, so we drop the line verbosely
				# to make sure we get informed in case the process spits out new
				# commands at some point.
				self.line_dropped(sline)
				sys.stderr.write("Operation name %r unknown - skipping line '%s'" % (op_name, sline))
				# Note: Don't add this line to the failed lines, as we have to silently
				# drop it
				return failed_lines
			#END handle opcode
			
			# figure out stage
			if op_code not in self._seen_ops:
				self._seen_ops.append(op_code)
				op_code |= self.BEGIN
			# END begin opcode
			
			if message is None:
				message = ''
			# END message handling
			
			message = message.strip()
			done_token = ', done.'
			if message.endswith(done_token):
				op_code |= self.END
				message = message[:-len(done_token)]
			# END end message handling
			
			self._progress.update(op_code, cur_count, max_count, message, line)
			self._progress(message, line)
		# END for each sub line
		return failed_lines


class CmdPushInfo(PushInfo):
	"""
	Pure Python implementation of a PushInfo interface
	"""
	__slots__ = ('local_ref', 'remote_ref_string', 'flags', 'old_commit_binsha', 
				'_remotename_or_url', 'repo', 'summary')
	
	_flag_map = {	'X' : PushInfo.NO_MATCH, 
					'-' : PushInfo.DELETED, '*' : 0,
					'+' : PushInfo.FORCED_UPDATE, 
					' ' : PushInfo.FAST_FORWARD, 
					'=' : PushInfo.UP_TO_DATE, 
					'!' : PushInfo.ERROR }
	
	def __init__(self, flags, local_ref, remote_ref_string, repo, remotename_or_url, old_commit_binsha=None, 
					summary=''):
		""" Initialize a new instance """
		self.flags = flags
		self.local_ref = local_ref
		self.repo = repo
		self.remote_ref_string = remote_ref_string
		self._remotename_or_url = remotename_or_url
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
			return TagReference(self.repo, self.remote_ref_string)
		elif self.remote_ref_string.startswith("refs/heads"):
			remote_ref = Reference(self.repo, self.remote_ref_string)
			if '/' in self._remotename_or_url:
				sys.stderr.write("Cannot provide RemoteReference instance if it was created from a url instead of of a remote name: %s. Returning Reference instance instead" % sefl._remotename_or_url)
				return remote_ref
			#END assert correct input
			return RemoteReference(self.repo, "refs/remotes/%s/%s" % (str(self._remotename_or_url), remote_ref.name))
		else:
			raise ValueError("Could not handle remote ref: %r" % self.remote_ref_string)
		# END 
		
	@classmethod
	def _from_line(cls, repo, remotename_or_url, line):
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
			from_ref = Reference.from_path(repo, from_ref_string)
		
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
			old_commit_binsha = repo.resolve(old_sha)
		# END message handling
		
		return cls(flags, from_ref, to_ref_string, repo, remotename_or_url, old_commit_binsha, summary)
		

class CmdFetchInfo(FetchInfo):
	"""
	Pure python implementation of a FetchInfo interface
	"""
	__slots__ = ('ref','old_commit_binsha', 'flags', 'note')
	
	#							  %c	%-*s %-*s			  -> %s		  (%s)
	re_fetch_result = re.compile("^\s*(.) (\[?[\w\s\.]+\]?)\s+(.+) -> ([/\w_\+\.-]+)(	 \(.*\)?$)?")
	
	_flag_map = {	'!' : FetchInfo.ERROR, 
					'+' : FetchInfo.FORCED_UPDATE, 
					'-' : FetchInfo.TAG_UPDATE, 
					'*' : 0,
					'=' : FetchInfo.HEAD_UPTODATE, 
					' ' : FetchInfo.FAST_FORWARD } 
	
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
		and return a new CmdFetchInfo object representing this information.
		
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
		elif ref_type_name in ("remote-tracking", "branch"):
			# note: remote-tracking is just the first part of the 'remote-tracking branch' token.
			# We don't parse it correctly, but its enough to know what to do, and its new in git 1.7something
			ref_type = RemoteReference
		elif ref_type_name == "tag":
			ref_type = TagReference
		else:
			raise TypeError("Cannot handle reference type: %r" % ref_type_name)
		#END handle ref type
			
		# create ref instance
		if ref_type is SymbolicReference:
			remote_local_ref = ref_type(repo, "FETCH_HEAD") 
		else:
			# determine prefix. Tags are usually pulled into refs/tags, they may have subdirectories.
			# It is not clear sometimes where exactly the item is, unless we have an absolute path as indicated
			# by the 'ref/' prefix. Otherwise even a tag could be in refs/remotes, which is when it will have the
			# 'tags/' subdirectory in its path.
			# We don't want to test for actual existence, but try to figure everything out analytically.
			ref_path = None
			remote_local_ref = remote_local_ref.strip()
			if remote_local_ref.startswith(Reference._common_path_default + "/"):
				# always use actual type if we get absolute paths
				# Will always be the case if something is fetched outside of refs/remotes (if its not a tag)
				ref_path = remote_local_ref
				if ref_type is not TagReference and not remote_local_ref.startswith(RemoteReference._common_path_default + "/"):
					ref_type = Reference
				#END downgrade remote reference
			elif ref_type is TagReference and 'tags/' in remote_local_ref:
				# even though its a tag, it is located in refs/remotes
				ref_path = join_path(RemoteReference._common_path_default, remote_local_ref)
			else:
				ref_path = join_path(ref_type._common_path_default, remote_local_ref)
			#END obtain refpath
			
			# even though the path could be within the git conventions, we make 
			# sure we respect whatever the user wanted, and disabled path checking
			remote_local_ref = ref_type(repo, ref_path, check_path=False)
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
				old_commit_binsha = repo.resolve(operation.split(split_token)[0])
			# END handle refspec
		# END reference flag handling
		
		return cls(remote_local_ref, flags, note, old_commit_binsha)
		

class GitCommandMixin(object):
	"""A mixin to provide the git command object through the git property"""
	
	def __init__(self, *args, **kwargs):
		"""Initialize this instance with the root and a git command"""
		super(GitCommandMixin, self).__init__(*args, **kwargs)
		self._git = Git(self.working_dir)
	
	@property
	def git(self):
		return self._git
	

class CmdObjectDBRMixin(object):
	"""A mixing implementing object reading through a git command
	It will create objects only in the loose object database.
	:note: for now, we use the git command to do all the lookup, just until he 
		have packs and the other implementations
	"""
	#{ ODB Interface
	# overrides from PureOdb Implementation, which is responsible only for writing
	# objects
	def info(self, sha):
		hexsha, typename, size = self._git.get_object_header(bin_to_hex(sha))
		return OInfo(hex_to_bin(hexsha), typename, size)
		
	def stream(self, sha):
		"""For now, all lookup is done by git itself
		:note: As we don't know when the stream is actually read (and if it is 
			stored for later use) we read the data rigth away and cache it.
			This has HUGE performance implication, both for memory as for 
			reading/deserializing objects, but we have no other choice in order
			to make the database behaviour consistent with other implementations !"""
		
		hexsha, typename, size, data = self._git.get_object_data(bin_to_hex(sha))
		return OStream(hex_to_bin(hexsha), typename, size, StringIO(data))
		
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
	
	#} END odb interface
	

class CmdTransportMixin(TransportDB):
	"""A mixin requiring the .git property as well as repository paths
	
	It will create objects only in the loose object database.
	:note: for now, we use the git command to do all the lookup, just until he 
		have packs and the other implementations
	"""
	
	#{ Transport DB interface
	
	def push(self, url, refspecs=None, progress=None, **kwargs):
		"""Push given refspecs using the git default implementation
		:param url: may be a remote name or a url
		:param refspecs: single string, RefSpec instance or list of such or None.
		:param progress: RemoteProgress derived instance or None
		:param **kwargs: Additional arguments to be passed to the git-push process"""
		progress = CmdRemoteProgress(progress)
		proc = self._git.push(url, refspecs, porcelain=True, as_process=True, **add_progress(kwargs, self.git, progress))
		return get_push_info(self, url, proc, progress)
		
	def pull(self, url, refspecs=None, progress=None, **kwargs):
		"""Fetch and merge the given refspecs. 
		If not refspecs are given, the merge will only work properly if you 
		have setup upstream (tracking) branches.
		:param url: may be a remote name or a url
		:param refspecs: see push()
		:param progress: see push()"""
		progress = CmdRemoteProgress(progress)
		proc = self._git.pull(url, refspecs, with_extended_output=True, as_process=True, v=True, **add_progress(kwargs, self.git, progress))
		return get_fetch_info_from_stderr(self, proc, progress)
		
	def fetch(self, url, refspecs=None, progress=None, **kwargs):
		"""Fetch the latest changes
		:param url: may be a remote name or a url
		:param refspecs: see push()
		:param progress: see push()"""
		progress = CmdRemoteProgress(progress)
		proc = self._git.fetch(url, refspecs, with_extended_output=True, as_process=True, v=True, **add_progress(kwargs, self.git, progress))
		return get_fetch_info_from_stderr(self, proc, progress)
		
	#} end transport db interface
	
	
class CmdHighLevelRepository(HighLevelRepository):
	"""An intermediate interface carrying advanced git functionality that can be used
	in other comound repositories which do not implement this functionality themselves.
	
	The mixin must be used with repositories compatible to the GitCommandMixin.
	
	:note: at some point, methods provided here are supposed to be provided by custom interfaces"""
	DAEMON_EXPORT_FILE = 'git-daemon-export-ok'
	
	# precompiled regex
	re_whitespace = re.compile(r'\s+')
	re_hexsha_only = re.compile('^[0-9A-Fa-f]{40}$')
	re_hexsha_shortened = re.compile('^[0-9A-Fa-f]{4,40}$')
	re_author_committer_start = re.compile(r'^(author|committer)')
	re_tab_full_line = re.compile(r'^\t(.*)$')
	
	#{ Configuration
	CommitCls = Commit
	GitCls = Git
	#} END configuration
	
	def daemon_export():
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

		return property(_get_daemon_export, _set_daemon_export,
						doc="If True, git-daemon may export this repository")
		
	daemon_export = daemon_export()

	def is_dirty(self, index=True, working_tree=True, untracked_files=False):
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
				elif info['id'] != firstpart:
					info = {'id': firstpart}
					blames.append([commits.get(firstpart), []])
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
								c = self.CommitCls(	 self, hex_to_bin(sha),
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
							blames[-1][1].append(text)
							info = { 'id' : sha }
						# END if we collected commit info
					# END distinguish filename,summary,rest
				# END distinguish author|committer vs filename,summary,rest
			# END distinguish hexsha vs other information
		return blames

	@classmethod
	def init(cls, path=None, mkdir=True, **kwargs):
		"""
		:parm kwargs:
			keyword arguments serving as additional options to the git-init command

		For more information, see the respective docs of HighLevelRepository"""

		if mkdir and path and not os.path.exists(path):
			os.makedirs(path, 0755)

		# git command automatically chdir into the directory
		git = cls.GitCls(path)
		output = git.init(**kwargs)
		return cls(path)

	@classmethod
	def _clone(cls, git, url, path, progress, **kwargs):
		# special handling for windows for path at which the clone should be 
		# created.
		# tilde '~' will be expanded to the HOME no matter where the ~ occours. Hence
		# we at least give a proper error instead of letting git fail
		prev_cwd = None
		prev_path = None
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
			if progress is not None:
				digest_process_messages(proc.stderr, progress)
			#END digest progress messages
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
		repo = cls(os.path.abspath(path))
		if repo.remotes:
			repo.remotes[0].config_writer.set_value('url', repo.remotes[0].url.replace("\\\\", "\\").replace("\\", "/"))
		# END handle remote repo
		return repo

	def clone(self, path, progress = None, **kwargs):
		"""
		:param kwargs:
			All remaining keyword arguments are given to the git-clone command
			
		For more information, see the respective method in HighLevelRepository"""
		return self._clone(self.git, self.git_dir, path, CmdRemoteProgress(progress), **kwargs)

	@classmethod
	def clone_from(cls, url, to_path, progress = None, **kwargs):
		"""
		:param kwargs: see the ``clone`` method
		For more information, see the respective method in the HighLevelRepository"""
		return cls._clone(cls.GitCls(os.getcwd()), url, to_path, CmdRemoteProgress(progress), **kwargs)

	def archive(self, ostream, treeish=None, prefix=None,  **kwargs):
		"""For all args see HighLevelRepository interface
		:parm kwargs:
			Additional arguments passed to git-archive
			NOTE: Use the 'format' argument to define the kind of format. Use 
			specialized ostreams to write any format supported by python

		:raise GitCommandError: in case something went wrong"""
		if treeish is None:
			treeish = self.head.commit
		if prefix and 'prefix' not in kwargs:
			kwargs['prefix'] = prefix 
		kwargs['output_stream'] = ostream
		
		self.git.archive(treeish, **kwargs)
		return self
