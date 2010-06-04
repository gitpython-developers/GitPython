"""Contains basic c-functions which usually contain performance critical code
Keeping this code separate from the beginning makes it easier to out-source
it into c later, if required"""

from git.errors import (
	BadObjectType
	)

import zlib
decompressobj = zlib.decompressobj


# INVARIANTS
type_id_to_type_map = 	{
							1 : "commit",
							2 : "tree",
							3 : "blob",
							4 : "tag"
						}

# used when dealing with larger streams
chunk_size = 1000*1000

__all__ = ('is_loose_object', 'loose_object_header_info', 'object_header_info', 
			'write_object' )

#{ Routines

def is_loose_object(m):
	""":return: True the file contained in memory map m appears to be a loose object.
	Only the first two bytes are needed"""
	b0, b1 = map(ord, m[:2])
	word = (b0 << 8) + b1
	return b0 == 0x78 and (word % 31) == 0

def loose_object_header_info(m):
	""":return: tuple(type_string, uncompressed_size_in_bytes) the type string of the 
		object as well as its uncompressed size in bytes.
	:param m: memory map from which to read the compressed object data"""
	decompress_size = 8192		# is used in cgit as well
	hdr = decompressobj().decompress(m, decompress_size)
	type_name, size = hdr[:hdr.find("\0")].split(" ")
	return type_name, int(size)
	
def object_header_info(m):
	""":return: tuple(type_string, uncompressed_size_in_bytes 
	:param mmap: mapped memory map. It will be 
		seeked to the actual start of the object contents, which can be used
		to initialize a zlib decompress object.
	:note: This routine can only handle new-style objects which are assumably contained
		in packs
		"""
	assert not is_loose_object(m), "Use loose_object_header_info instead"
	
	c = b0							# first byte
	i = 1							# next char to read
	type_id = (c >> 4) & 7			# numeric type
	size = c & 15					# starting size
	s = 4							# starting bit-shift size
	while c & 0x80:
		c = ord(m[i])
		i += 1
		size += (c & 0x7f) << s
		s += 7
	# END character loop
	
	# finally seek the map to the start of the data stream
	m.seek(i)
	try:
		return (type_id_to_type_map[type_id], size)
	except KeyError:
		# invalid object type - we could try to be smart now and decode part 
		# of the stream to get the info, problem is that we had trouble finding 
		# the exact start of the content stream
		raise BadObjectType(type_id)
	# END handle exceptions
	
def write_object(type, size, read, write, chunk_size=chunk_size):
	"""Write the object as identified by type, size and source_stream into the 
	target_stream
	
	:param type: type string of the object
	:param size: amount of bytes to write from source_stream
	:param read: read method of a stream providing the content data
	:param write: write method of the output stream
	:param close_target_stream: if True, the target stream will be closed when
		the routine exits, even if an error is thrown
	:return: The actual amount of bytes written to stream, which includes the header and a trailing newline"""
	tbw = 0												# total num bytes written
	
	# WRITE HEADER: type SP size NULL
	tbw += write("%s %i\0" % (type, size))
	tbw += stream_copy(read, write, size, chunk_size)
	
	return tbw

def stream_copy(read, write, size, chunk_size):
	"""Copy a stream up to size bytes using the provided read and write methods, 
	in chunks of chunk_size
	:note: its much like stream_copy utility, but operates just using methods"""
	dbw = 0												# num data bytes written
	
	# WRITE ALL DATA UP TO SIZE
	while True:
		cs = min(chunk_size, size-dbw)
		data_len = write(read(cs))
		dbw += data_len
		if data_len < cs or dbw == size:
			break
		# END check for stream end
	# END duplicate data
	return dbw
	
	
#} END routines
