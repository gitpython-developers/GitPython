import binascii
import os
import zlib
from cStringIO import StringIO
from git.utils import make_sha
import errno
from fun import chunk_size

__all__ = ('FDSha1Writer', )

#{ Routines

hex_to_bin = binascii.a2b_hex
bin_to_hex = binascii.b2a_hex

def to_hex_sha(sha):
	""":return: hexified version  of sha"""
	if len(sha) == 40:
		return sha
	return bin_to_hex(sha)
	
def to_bin_sha(sha):
	if len(sha) == 20:
		return sha
	return hex_to_bin(sha)

# errors
ENOENT = errno.ENOENT

# os shortcuts
exists = os.path.exists
mkdir = os.mkdir
isdir = os.path.isdir
rename = os.rename
dirname = os.path.dirname
join = os.path.join
read = os.read
write = os.write
close = os.close

# ZLIB configuration
# used when compressing objects
Z_BEST_SPEED = 1

#} END Routines


#{ Classes

class FDCompressedSha1Writer(object):
	"""Digests data written to it, making the sha available, then compress the 
	data and write it to the file descriptor
	:note: operates on raw file descriptors
	:note: for this to work, you have to use the close-method of this instance"""
	__slots__ = ("fd", "sha1", "zip")
	
	# default exception
	exc = IOError("Failed to write all bytes to filedescriptor")
	
	def __init__(self, fd):
		self.fd = fd
		self.sha1 = make_sha("")
		self.zip = zlib.compressobj(Z_BEST_SPEED)

	def write(self, data):
		""":raise IOError: If not all bytes could be written
		:return: lenght of incoming data"""
		self.sha1.update(data)
		cdata = self.zip.compress(data)
		bytes_written = write(self.fd, cdata)
		if bytes_written != len(cdata):
			raise self.exc
		return bytes_written

	def sha(self, as_hex = False):
		""":return: sha so far
		:param as_hex: if True, sha will be hex-encoded, binary otherwise"""
		if as_hex:
			return self.sha1.hexdigest()
		return self.sha1.digest()

	def close(self):
		remainder = self.zip.flush()
		if write(self.fd, remainder) != len(remainder):
			raise self.exc
		return close(self.fd)


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
	__slots__ = ('_m', '_zip', '_buf', '_buflen', '_br', '_cws', '_cwe', '_s', '_cs', '_close')
	
	def __init__(self, m, close_on_deletion, cs = 128*1024):
		"""Initialize with mmap and chunk_size for stream reading"""
		self._m = m
		self._zip = zlib.decompressobj()
		self._buf = None						# buffer of decompressed bytes
		self._buflen = 0						# length of bytes in buffer
		self._s = 0								# size of uncompressed data to read in total
		self._br = 0							# num uncompressed bytes read
		self._cws = 0							# start byte of compression window
		self._cwe = 0							# end byte of compression window
		self._cs = cs							# chunk size (when reading from zip) 
		self._close = close_on_deletion			# close the memmap on deletion ?
		
	def __del__(self):
		if self._close:
			self._m.close()
		# END handle resource freeing
		
	def initialize(self, size=0):
		"""Initialize this instance for acting as a read-only stream for size bytes.
		:param size: size in bytes to be decompresed before being depleted.
			If 0, default object header information is parsed from the data, 
			returning a tuple of (type_string, uncompressed_size)
			If not 0, the size will be used, and None is returned.
		:note: must only be called exactly once"""
		if size:
			self._s = size
			return
		# END handle size
		
		# read header
		maxb = 8192
		self._s = maxb
		hdr = self.read(maxb)
		hdrend = hdr.find("\0")
		type, size = hdr[:hdrend].split(" ")
		self._s = int(size)
		
		# adjust internal state to match actual header length that we ignore
		# The buffer will be depleted first on future reads
		self._br = 0
		hdrend += 1									# count terminating \0
		self._buf = StringIO(hdr[hdrend:])
		self._buflen = len(hdr) - hdrend
		
		return type, size
		
	def read(self, size=-1):
		if size < 1:
			size = self._s - self._br
		else:
			size = min(size, self._s - self._br)
		# END clamp size
		
		if size == 0:
			return str()
		# END handle depletion
		
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
				dat = self._buf.getvalue()		# ouch, duplicates data
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
		if self._zip.unconsumed_tail:
			# move the window, make it as large as size demands. For code-clarity, 
			# we just take the chunk from our map again instead of reusing the unconsumed
			# tail. The latter one would safe some memory copying, but we could end up
			# with not getting enough data uncompressed, so we had to sort that out as well.
			# Now we just assume the worst case, hence the data is uncompressed and the window
			# needs to be as large as the uncompressed bytes we want to read.
			self._cws = self._cwe - len(self._zip.unconsumed_tail)
			self._cwe = self._cws + size
			indata = self._m[self._cws:self._cwe]		# another copy ... :(
		else:
			cws = self._cws
			self._cws = self._cwe
			self._cwe = cws + size 
			indata = self._m[self._cws:self._cwe]		# ... copy it again :(
		# END handle tail
		
		dcompdat = self._zip.decompress(indata, size)
		self._br += len(dcompdat)
		
		if dat:
			return dat + dcompdat
		return dcompdat
		
#} END classes 
