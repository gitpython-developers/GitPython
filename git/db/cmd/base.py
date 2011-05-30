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
							hex_to_bin
						)
from git.db.compat import RepoCompatibilityInterface
from git.util import RemoteProgress
from git.db.interface import FetchInfo as GitdbFetchInfo
from git.db.interface import PushInfo as GitdbPushInfo
from git.db.interface import HighLevelRepository

from git.util import  join_path
from git.util import join
from git.cmd import Git
from git.refs import (
						Reference,
						RemoteReference,
						SymbolicReference, 
						TagReference
					)

import re
import sys


__all__ = ('CmdTransportMixin', 'RemoteProgress', 'GitCommandMixin', 
			'CmdObjectDBRMixin', 'CmdHighLevelRepository')


#{ Utilities

def touch(filename):
	fp = open(filename, "a")
	fp.close()

#} END utilities

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
		"""For now, all lookup is done by git itself"""
		hexsha, typename, size, stream = self._git.stream_object_data(bin_to_hex(sha))
		return OStream(hex_to_bin(hexsha), typename, size, stream)
		
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
	

class CmdTransportMixin(object):
	"""A mixin requiring the .git property as well as repository paths
	
	It will create objects only in the loose object database.
	:note: for now, we use the git command to do all the lookup, just until he 
		have packs and the other implementations
	"""
	
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
		"""
		:parm kwargs:
			keyword arguments serving as additional options to the git-init command

		For more information, see the respective docs of HighLevelRepository"""

		if mkdir and path and not os.path.exists(path):
			os.makedirs(path, 0755)

		# git command automatically chdir into the directory
		git = Git(path)
		output = git.init(**kwargs)
		return Repo(path)

	@classmethod
	def _clone(cls, git, url, path, **kwargs):
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
		repo = cls(os.path.abspath(path))
		if repo.remotes:
			repo.remotes[0].config_writer.set_value('url', repo.remotes[0].url.replace("\\\\", "\\").replace("\\", "/"))
		# END handle remote repo
		return repo

	def clone(self, path, **kwargs):
		""":param kwargs:
			All remaining keyword arguments are given to the git-clone command
			
		For more information, see the respective method in HighLevelRepository"""
		return self._clone(self.git, self.git_dir, path, **kwargs)

	@classmethod
	def clone_from(cls, url, to_path, **kwargs):
		"""
		:param kwargs: see the ``clone`` method
		For more information, see the respective method in the HighLevelRepository"""
		return cls._clone(type(self.git)(os.getcwd()), url, to_path, **kwargs)

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
