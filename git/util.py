# utils.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import re
import sys
import time
import tempfile

from gitdb.util import (
							make_sha, 
							LockedFD, 
							file_contents_ro, 
							LazyMixin, 
							to_hex_sha, 
							to_bin_sha,
							join_path, 
							join_path_native,
							to_native_path,
							to_native_path_linux,
							to_native_path_windows,
							assure_directory_exists,
							LockFile,
							BlockingLockFile,
							Actor,
							Iterable,
							stream_copy,
							IterableList,
							get_user_id
						)

__all__ = ( "stream_copy", "join_path", "to_native_path_windows", "to_native_path_linux", 
			"join_path_native", "Stats", "IndexFileSHA1Writer", "Iterable", "IterableList", 
			"BlockingLockFile", "LockFile", 'Actor', 'get_user_id', 'assure_directory_exists',
			'RemoteProgress', 'RepoAliasMixin')

#{ Classes

class RemoteProgress(object):
	"""
	Handler providing an interface to parse progress information emitted by git-push
	and git-fetch and to dispatch callbacks allowing subclasses to react to the progress.
	"""
	_num_op_codes = 5
	BEGIN, END, COUNTING, COMPRESSING, WRITING =  [1 << x for x in range(_num_op_codes)]
	STAGE_MASK = BEGIN|END
	OP_MASK = ~STAGE_MASK
	
	__slots__ = ("_cur_line", "_seen_ops")
	re_op_absolute = re.compile("(remote: )?([\w\s]+):\s+()(\d+)()(.*)")
	re_op_relative = re.compile("(remote: )?([\w\s]+):\s+(\d+)% \((\d+)/(\d+)\)(.*)")
	
	def __init__(self):
		self._seen_ops = list()
	
	def _parse_progress_line(self, line):
		"""Parse progress information from the given line as retrieved by git-push
		or git-fetch
		
		:return: list(line, ...) list of lines that could not be processed"""
		# handle
		# Counting objects: 4, done. 
		# Compressing objects:	50% (1/2)	\rCompressing objects: 100% (2/2)	\rCompressing objects: 100% (2/2), done.
		self._cur_line = line
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
				self.line_dropped(sline)
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
			else:
				raise ValueError("Operation name %r unknown" % op_name)
			
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
			
			self.update(op_code, cur_count, max_count, message)
			self(message)
		# END for each sub line
		return failed_lines
	
	def line_dropped(self, line):
		"""Called whenever a line could not be understood and was therefore dropped."""
		pass
	
	def update(self, op_code, cur_count, max_count=None, message=''):
		"""Called whenever the progress changes
		
		:param op_code:
			Integer allowing to be compared against Operation IDs and stage IDs.
			
			Stage IDs are BEGIN and END. BEGIN will only be set once for each Operation 
			ID as well as END. It may be that BEGIN and END are set at once in case only
			one progress message was emitted due to the speed of the operation.
			Between BEGIN and END, none of these flags will be set
			
			Operation IDs are all held within the OP_MASK. Only one Operation ID will 
			be active per call.
		:param cur_count: Current absolute count of items
			
		:param max_count:
			The maximum count of items we expect. It may be None in case there is 
			no maximum number of items or if it is (yet) unknown.
		
		:param message:
			In case of the 'WRITING' operation, it contains the amount of bytes
			transferred. It may possibly be used for other purposes as well.
		
		You may read the contents of the current line in self._cur_line"""
		pass
	
	def __call__(self, message):
		"""Same as update, but with a simpler interface which only provides the
		message of the operation
		:note: This method will be called in addition to the update method. It is 
			up to you which one you implement"""
		pass

class RepoAliasMixin(object):
	"""Simple utility providing a repo-property which resolves to the 'odb' attribute
	of the actual type. This is for api compatability only, as the types previously
	held repository instances, now they hold odb instances instead"""
	__slots__ = tuple()
	
	@property
	def repo(self):
		return self.odb
	

class Stats(object):
	"""
	Represents stat information as presented by git at the end of a merge. It is 
	created from the output of a diff operation.
	
	``Example``::
	
	 c = Commit( sha1 )
	 s = c.stats
	 s.total		 # full-stat-dict
	 s.files		 # dict( filepath : stat-dict )
	 
	``stat-dict``
	
	A dictionary with the following keys and values::
	 
	  deletions = number of deleted lines as int
	  insertions = number of inserted lines as int
	  lines = total number of lines changed as int, or deletions + insertions
	  
	``full-stat-dict``
	
	In addition to the items in the stat-dict, it features additional information::
	
	 files = number of changed files as int"""
	__slots__ = ("total", "files")
	
	def __init__(self, total, files):
		self.total = total
		self.files = files

	@classmethod
	def _list_from_string(cls, repo, text):
		"""Create a Stat object from output retrieved by git-diff.
		
		:return: git.Stat"""
		hsh = {'total': {'insertions': 0, 'deletions': 0, 'lines': 0, 'files': 0}, 'files': dict()}
		for line in text.splitlines():
			(raw_insertions, raw_deletions, filename) = line.split("\t")
			insertions = raw_insertions != '-' and int(raw_insertions) or 0
			deletions = raw_deletions != '-' and int(raw_deletions) or 0
			hsh['total']['insertions'] += insertions
			hsh['total']['deletions'] += deletions
			hsh['total']['lines'] += insertions + deletions
			hsh['total']['files'] += 1
			hsh['files'][filename.strip()] = {'insertions': insertions,
											  'deletions': deletions,
											  'lines': insertions + deletions}
		return Stats(hsh['total'], hsh['files'])


class IndexFileSHA1Writer(object):
	"""Wrapper around a file-like object that remembers the SHA1 of 
	the data written to it. It will write a sha when the stream is closed
	or if the asked for explicitly usign write_sha.
	
	Only useful to the indexfile
	
	:note: Based on the dulwich project"""
	__slots__ = ("f", "sha1")
	
	def __init__(self, f):
		self.f = f
		self.sha1 = make_sha("")

	def write(self, data):
		self.sha1.update(data)
		return self.f.write(data)

	def write_sha(self):
		sha = self.sha1.digest()
		self.f.write(sha)
		return sha

	def close(self):
		sha = self.write_sha()
		self.f.close()
		return sha

	def tell(self):
		return self.f.tell()


#} END classes
