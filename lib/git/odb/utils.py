import binascii
import os
import zlib
from git.utils import make_sha

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
		self.zip = zlib.compressobj()

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


#} END classes 
