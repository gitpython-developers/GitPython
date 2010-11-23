from head import Head
from git.util import join_path
from gitdb.util import (
						join,
						file_contents_ro_filepath
					)

from git.objects.util import (
								Actor, 
								parse_date,
								Serializable, 
								utctz_to_altz,
								altz_to_utctz_str,
							)

import os
import re

__all__ = ["RefLog", "RefLogEntry"]


class RefLogEntry(tuple):
	"""Named tuple allowing easy access to the revlog data fields"""
	_fmt = "%s %s %s <%s> %i %s\t%s\n"
	_re_hexsha_only = re.compile('^[0-9A-Fa-f]{40}$')
	__slots__ = tuple()
	
	def __repr__(self):
		"""Representation of ourselves in git reflog format"""
		act = self.actor
		time = self.time
		return self._fmt % (self.oldhexsha, self.newhexsha, act.name, act.email, 
							time[0], altz_to_utctz_str(time[1]), self.message)
	
	@property
	def oldhexsha(self):
		"""The hexsha to the commit the ref pointed to before the change""" 
		return self[0]
		
	@property
	def newhexsha(self):
		"""The hexsha to the commit the ref now points to, after the change"""
		return self[1]
		
	@property
	def actor(self):
		"""Actor instance, providing access"""
		return self[2]
		
	@property
	def time(self):
		"""time as tuple:
		
		* [0] = int(time)
		* [1] = int(timezone_offset) in time.altzone format """
		return self[3]
		
	@property
	def message(self):
		"""Message describing the operation that acted on the reference"""
		return self[4]
	
	@classmethod
	def new(self, oldhexsha, newhexsha, actor, time, tz_offset, message):
		""":return: New instance of a RefLogEntry"""
		if not isinstance(actor, Actor):
			raise ValueError("Need actor instance, got %s" % actor)
		# END check types 
		return RefLogEntry((oldhexsha, newhexsha, actor, (time, tz_offset), message))
		
	@classmethod
	def from_line(cls, line):
		""":return: New RefLogEntry instance from the given revlog line.
		:param line: line without trailing newline
		:raise ValueError: If line could not be parsed"""
		try:
			info, msg = line.split('\t', 2)
		except ValueError:
			raise ValueError("line is missing tab separator")
		#END handle first plit
		oldhexsha = info[:40]
		newhexsha = info[41:81]
		for hexsha in (oldhexsha, newhexsha):
			if not cls._re_hexsha_only.match(hexsha):
				raise ValueError("Invalid hexsha: %s" % hexsha)
			# END if hexsha re doesn't match
		#END for each hexsha
		
		email_end = info.find('>', 82)
		if email_end == -1:
			raise ValueError("Missing token: >")
		#END handle missing end brace
		
		actor = Actor._from_string(info[82:email_end+1])
		time, tz_offset = parse_date(info[email_end+2:])
		
		return RefLogEntry((oldhexsha, newhexsha, actor, (time, tz_offset), msg))
		

class RefLog(list, Serializable):
	"""A reflog contains reflog entries, each of which defines a certain state
	of the head in question. Custom query methods allow to retrieve log entries 
	by date or by other criteria.
	
	Reflog entries are orded, the first added entry is first in the list, the last
	entry, i.e. the last change of the head or reference, is last in the list."""
	
	__slots__ = tuple()
	
	#{ Interface
	
	@classmethod
	def from_file(cls, filepath):
		"""
		:return: a new RefLog instance containing all entries from the reflog 
			at the given filepath
		:param filepath: path to reflog 
		:raise ValueError: If the file could not be read or was corrupted in some way"""
		inst = cls()
		fmap = file_contents_ro_filepath(filepath, stream=False, allow_mmap=True)
		try:
			inst._deserialize(fmap)
		finally:
			fmap.close()
		#END handle closing of handle 
		return inst
	
	@classmethod
	def path(cls, ref):
		"""
		:return: string to absolute path at which the reflog of the given ref 
			instance would be found. The path is not guaranteed to point to a valid 
			file though.
		:param ref: SymbolicReference instance"""
		return join(ref.repo.git_dir, "logs", ref.path)
		
	@classmethod
	def iter_entries(cls, stream):
		"""
		:return: Iterator yielding RefLogEntry instances, one for each line read 
			sfrom the given stream.
		:param stream: file-like object containing the revlog in its native format
			or basestring instance pointing to a file to read"""
		new_entry = RefLogEntry.from_line
		if isinstance(stream, basestring):
			stream = file_contents_ro_filepath(stream)
		#END handle stream type
		while True:
			line = stream.readline()
			if not line:
				return
			yield new_entry(line.strip())
		#END endless loop
	
	def to_file(self, filepath):
		"""Write the contents of the reflog instance to a file at the given filepath.
		:param filepath: path to file, parent directories are assumed to exist"""
		fp = open(filepath, 'wb')
		try:
			self._serialize(fp)
		finally:
			fp.close()
		#END handle file streams
	
	#} END interface
	
	#{ Serializable Interface
	def _serialize(self, stream):
		lm1 = len(self) - 1
		write = stream.write
		
		# write all entries
		for i, e in enumerate(self):
			write(repr(e))
		#END for each entry
	
	def _deserialize(self, stream):
		self.extend(self.iter_entries(stream))
	#} END serializable interface
