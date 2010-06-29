# blob.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from mimetypes import guess_type
import base

__all__ = ('Blob', )

class Blob(base.IndexObject):
	"""A Blob encapsulates a git blob object"""
	DEFAULT_MIME_TYPE = "text/plain"
	type = "blob"

	__slots__ = "data"

	def _set_cache_(self, attr):
		if attr == "data":
			ostream = self.repo.odb.stream(self.binsha)
			self.size = ostream.size
			self.data = ostream.read()
			# assert ostream.type == self.type, _assertion_msg_format % (self.binsha, ostream.type, self.type)
		else:
			super(Blob, self)._set_cache_(attr)
		# END handle data

	@property
	def mime_type(self):
		"""
		:return: String describing the mime type of this file (based on the filename)
		:note: Defaults to 'text/plain' in case the actual file type is unknown. """
		guesses = None
		if self.path:
			guesses = guess_type(self.path)
		return guesses and guesses[0] or self.DEFAULT_MIME_TYPE
