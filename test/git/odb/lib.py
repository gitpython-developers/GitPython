"""Utilities used in ODB testing"""
from git.odb import (
	OStream, 
	)
from git.odb.stream import Sha1Writer

import zlib
from cStringIO import StringIO

#{ Stream Utilities

class DummyStream(object):
		def __init__(self):
			self.was_read = False
			self.bytes = 0
			self.closed = False
			
		def read(self, size):
			self.was_read = True
			self.bytes = size
			
		def close(self):
			self.closed = True
			
		def _assert(self):
			assert self.was_read


class DeriveTest(OStream):
	def __init__(self, sha, type, size, stream, *args, **kwargs):
		self.myarg = kwargs.pop('myarg')
		self.args = args
		
	def _assert(self):
		assert self.args
		assert self.myarg


class ZippedStoreShaWriter(Sha1Writer):
	"""Remembers everything someone writes to it"""
	__slots__ = ('buf', 'zip')
	def __init__(self):
		Sha1Writer.__init__(self)
		self.buf = StringIO()
		self.zip = zlib.compressobj(1)	# fastest
	
	def __getattr__(self, attr):
		return getattr(self.buf, attr)
	
	def write(self, data):
		alen = Sha1Writer.write(self, data)
		self.buf.write(self.zip.compress(data))
		return alen
		
	def close(self):
		self.buf.write(self.zip.flush())


#} END stream utilitiess

