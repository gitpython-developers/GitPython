import zlib
from cStringIO import StringIO
from git.utils import make_sha
import errno

from utils import (
		to_hex_sha,
		to_bin_sha, 
		write, 
		close
	)

__all__ = ('OInfo', 'OStream', 'IStream', 'InvalidOInfo', 'InvalidOStream', 
			'DecompressMemMapReader', 'FDCompressedSha1Writer')


# ZLIB configuration
# used when compressing objects - 1 to 9 ( slowest )
Z_BEST_SPEED = 1


#{ ODB Bases

class OInfo(tuple):
	"""Carries information about an object in an ODB, provdiing information 
	about the sha of the object, the type_string as well as the uncompressed size
	in bytes.
	
	It can be accessed using tuple notation and using attribute access notation::
	
		assert dbi[0] == dbi.sha
		assert dbi[1] == dbi.type
		assert dbi[2] == dbi.size
	
	The type is designed to be as lighteight as possible."""
	__slots__ = tuple()
	
	def __new__(cls, sha, type, size):
		return tuple.__new__(cls, (sha, type, size))
	
	def __init__(self, *args):
		tuple.__init__(self)
	
	#{ Interface 
	@property
	def sha(self):
		return self[0]
		
	@property
	def type(self):
		return self[1]
		
	@property
	def size(self):
		return self[2]
	#} END interface


class OStream(OInfo):
	"""Base for object streams retrieved from the database, providing additional 
	information about the stream.
	Generally, ODB streams are read-only as objects are immutable"""
	__slots__ = tuple()
	
	def __new__(cls, sha, type, size, stream, *args, **kwargs):
		"""Helps with the initialization of subclasses"""
		return tuple.__new__(cls, (sha, type, size, stream))
	
	
	def __init__(self, *args, **kwargs):
		tuple.__init__(self)
	
	#{ Stream Reader Interface 
	
	def read(self, size=-1):
		return self[3].read(size)
		
	#} END stream reader interface


class IStream(list):
	"""Represents an input content stream to be fed into the ODB. It is mutable to allow 
	the ODB to record information about the operations outcome right in this instance.
	
	It provides interfaces for the OStream and a StreamReader to allow the instance
	to blend in without prior conversion.
	
	The only method your content stream must support is 'read'"""
	__slots__ = tuple()
	
	def __new__(cls, type, size, stream, sha=None):
		return list.__new__(cls, (sha, type, size, stream, None))
		
	def __init__(self, type, size, stream, sha=None):
		list.__init__(self, (sha, type, size, stream, None))
	
	#{ Interface 
	
	@property
	def hexsha(self):
		""":return: our sha, hex encoded, 40 bytes"""
		return to_hex_sha(self[0])
		
	@property
	def binsha(self):
		""":return: our sha as binary, 20 bytes"""
		return to_bin_sha(self[0])
		
	def _error(self):
		""":return: the error that occurred when processing the stream, or None"""
		return self[4]
		
	def _set_error(self, exc):
		"""Set this input stream to the given exc, may be None to reset the error"""
		self[4] = exc
			
	error = property(_error, _set_error)
	
	#} END interface
	
	#{ Stream Reader Interface
	
	def read(self, size=-1):
		"""Implements a simple stream reader interface, passing the read call on 
			to our internal stream"""
		return self[3].read(size)
		
	#} END stream reader interface 
	
	#{  interface
	
	def _set_sha(self, sha):
		self[0] = sha
		
	def _sha(self):
		return self[0]
		
	sha = property(_sha, _set_sha)
	
	
	def _type(self):
		return self[1]
	
	def _set_type(self, type):
		self[1] = type
		
	type = property(_type, _set_type)
	
	def _size(self):
		return self[2]
		
	def _set_size(self, size):
		self[2] = size
	
	size = property(_size, _set_size)
	
	def _stream(self):
		return self[3]
		
	def _set_stream(self, stream):
		self[3] = stream
	
	stream = property(_stream, _set_stream)
	
	#} END odb info interface 
		

class InvalidOInfo(tuple):
	"""Carries information about a sha identifying an object which is invalid in 
	the queried database. The exception attribute provides more information about
	the cause of the issue"""
	__slots__ = tuple()
	
	def __new__(cls, sha, exc):
		return tuple.__new__(cls, (sha, exc))
		
	def __init__(self, sha, exc):
		tuple.__init__(self, (sha, exc))
	
	@property
	def sha(self):
		return self[0]
		
	@property
	def error(self):
		""":return: exception instance explaining the failure"""
		return self[1]


class InvalidOStream(InvalidOInfo):
	"""Carries information about an invalid ODB stream"""
	__slots__ = tuple()
	
#} END ODB Bases


#{ RO Streams

class DecompressMemMapReader(object):
	"""Reads data in chunks from a memory map and decompresses it. The client sees 
	only the uncompressed data, respective file-like read calls are handling on-demand
	buffered decompression accordingly
	
	A constraint on the total size of bytes is activated, simulating 
	a logical file within a possibly larger physical memory area
	
	To read efficiently, you clearly don't want to read individual bytes, instead, 
	read a few kilobytes at least.
	
	:note: The chunk-size should be carefully selected as it will involve quite a bit 
		of string copying due to the way the zlib is implemented. Its very wasteful, 
		hence we try to find a good tradeoff between allocation time and number of 
		times we actually allocate. An own zlib implementation would be good here
		to better support streamed reading - it would only need to keep the mmap
		and decompress it into chunks, thats all ... """
	__slots__ = ('_m', '_zip', '_buf', '_buflen', '_br', '_cws', '_cwe', '_s', '_close')
	
	max_read_size = 512*1024		# currently unused
	
	def __init__(self, m, close_on_deletion, size):
		"""Initialize with mmap for stream reading
		:param m: must be content data - use new if you have object data and no size"""
		self._m = m
		self._zip = zlib.decompressobj()
		self._buf = None						# buffer of decompressed bytes
		self._buflen = 0						# length of bytes in buffer
		self._s = size							# size of uncompressed data to read in total
		self._br = 0							# num uncompressed bytes read
		self._cws = 0							# start byte of compression window
		self._cwe = 0							# end byte of compression window
		self._close = close_on_deletion			# close the memmap on deletion ?
		
	def __del__(self):
		if self._close:
			self._m.close()
		# END handle resource freeing
		
	def _parse_header_info(self):
		"""If this stream contains object data, parse the header info and skip the 
		stream to a point where each read will yield object content
		:return: parsed type_string, size"""
		# read header
		maxb = 512				# should really be enough, cgit uses 8192 I believe
		self._s = maxb
		hdr = self.read(maxb)
		hdrend = hdr.find("\0")
		type, size = hdr[:hdrend].split(" ")
		size = int(size)
		self._s = size
		
		# adjust internal state to match actual header length that we ignore
		# The buffer will be depleted first on future reads
		self._br = 0
		hdrend += 1									# count terminating \0
		self._buf = StringIO(hdr[hdrend:])
		self._buflen = len(hdr) - hdrend
		
		return type, size
		
	@classmethod
	def new(self, m, close_on_deletion=False):
		"""Create a new DecompressMemMapReader instance for acting as a read-only stream
		This method parses the object header from m and returns the parsed 
		type and size, as well as the created stream instance.
		:param m: memory map on which to oparate. It must be object data ( header + contents )
		:param close_on_deletion: if True, the memory map will be closed once we are 
			being deleted"""
		inst = DecompressMemMapReader(m, close_on_deletion, 0)
		type, size = inst._parse_header_info()
		return type, size, inst
		
	def read(self, size=-1):
		if size < 1:
			size = self._s - self._br
		else:
			size = min(size, self._s - self._br)
		# END clamp size
		
		if size == 0:
			return str()
		# END handle depletion
		
		# protect from memory peaks
		# If he tries to read large chunks, our memory patterns get really bad
		# as we end up copying a possibly huge chunk from our memory map right into
		# memory. This might not even be possible. Nonetheless, try to dampen the 
		# effect a bit by reading in chunks, returning a huge string in the end.
		# Our performance now depends on StringIO. This way we don't need two large
		# buffers in peak times, but only one large one in the end which is 
		# the return buffer
		# NO: We don't do it - if the user thinks its best, he is right. If he 
		# has trouble, he will start reading in chunks. According to our tests
		# its still faster if we read 10 Mb at once instead of chunking it.
		
		# if size > self.max_read_size:
			# sio = StringIO()
			# while size:
				# read_size = min(self.max_read_size, size)
				# data = self.read(read_size)
				# sio.write(data)
				# size -= len(data)
				# if len(data) < read_size:
					# break
			# # END data loop
			# sio.seek(0)
			# return sio.getvalue()
		# # END handle maxread
		# 
		# deplete the buffer, then just continue using the decompress object 
		# which has an own buffer. We just need this to transparently parse the 
		# header from the zlib stream
		dat = str()
		if self._buf:
			if self._buflen >= size:
				# have enough data
				dat = self._buf.read(size)
				self._buflen -= size
				self._br += size
				return dat
			else:
				dat = self._buf.read()		# ouch, duplicates data
				size -= self._buflen
				self._br += self._buflen
				
				self._buflen = 0
				self._buf = None
			# END handle buffer len
		# END handle buffer
		
		# decompress some data
		# Abstract: zlib needs to operate on chunks of our memory map ( which may 
		# be large ), as it will otherwise and always fill in the 'unconsumed_tail'
		# attribute which possible reads our whole map to the end, forcing 
		# everything to be read from disk even though just a portion was requested.
		# As this would be a nogo, we workaround it by passing only chunks of data, 
		# moving the window into the memory map along as we decompress, which keeps 
		# the tail smaller than our chunk-size. This causes 'only' the chunk to be
		# copied once, and another copy of a part of it when it creates the unconsumed
		# tail. We have to use it to hand in the appropriate amount of bytes durin g
		# the next read.
		tail = self._zip.unconsumed_tail
		if tail:
			# move the window, make it as large as size demands. For code-clarity, 
			# we just take the chunk from our map again instead of reusing the unconsumed
			# tail. The latter one would safe some memory copying, but we could end up
			# with not getting enough data uncompressed, so we had to sort that out as well.
			# Now we just assume the worst case, hence the data is uncompressed and the window
			# needs to be as large as the uncompressed bytes we want to read.
			self._cws = self._cwe - len(tail)
			self._cwe = self._cws + size
		else:
			cws = self._cws
			self._cws = self._cwe
			self._cwe = cws + size 
		# END handle tail
		
		
		# if window is too small, make it larger so zip can decompress something
		win_size = self._cwe - self._cws 
		if win_size < 8:
			self._cwe = self._cws + 8
		# END adjust winsize
		indata = self._m[self._cws:self._cwe]		# another copy ... :(
		
		# get the actual window end to be sure we don't use it for computations
		self._cwe = self._cws + len(indata)
			
		dcompdat = self._zip.decompress(indata, size)
		
		self._br += len(dcompdat)
		if dat:
			dcompdat = dat + dcompdat
			
		return dcompdat
		
#} END RO streams


#{ W Streams

class Sha1Writer(object):
	"""Simple stream writer which produces a sha whenever you like as it degests
	everything it is supposed to write"""
	__slots__ = "sha1"
	
	def __init__(self):
		self.sha1 = make_sha("")

	#{ Stream Interface

	def write(self, data):
		""":raise IOError: If not all bytes could be written
		:return: lenght of incoming data"""
		self.sha1.update(data)
		return len(data)

	# END stream interface 

	#{ Interface
	
	def sha(self, as_hex = False):
		""":return: sha so far
		:param as_hex: if True, sha will be hex-encoded, binary otherwise"""
		if as_hex:
			return self.sha1.hexdigest()
		return self.sha1.digest()
	
	#} END interface 

class FDCompressedSha1Writer(Sha1Writer):
	"""Digests data written to it, making the sha available, then compress the 
	data and write it to the file descriptor
	:note: operates on raw file descriptors
	:note: for this to work, you have to use the close-method of this instance"""
	__slots__ = ("fd", "sha1", "zip")
	
	# default exception
	exc = IOError("Failed to write all bytes to filedescriptor")
	
	def __init__(self, fd):
		super(FDCompressedSha1Writer, self).__init__()
		self.fd = fd
		self.zip = zlib.compressobj(Z_BEST_SPEED)

	#{ Stream Interface

	def write(self, data):
		""":raise IOError: If not all bytes could be written
		:return: lenght of incoming data"""
		self.sha1.update(data)
		cdata = self.zip.compress(data)
		bytes_written = write(self.fd, cdata)
		if bytes_written != len(cdata):
			raise self.exc
		return len(data)

	def close(self):
		remainder = self.zip.flush()
		if write(self.fd, remainder) != len(remainder):
			raise self.exc
		return close(self.fd)

	#} END stream interface

#} END W streams
