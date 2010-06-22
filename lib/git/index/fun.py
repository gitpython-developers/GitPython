"""
Contains standalone functions to accompany the index implementation and make it
more versatile
"""
from stat import S_IFDIR
from cStringIO import StringIO

from git.errors import UnmergedEntriesError
from git.objects.fun import tree_to_stream
from git.utils import (
							IndexFileSHA1Writer, 
						)

from typ import (
					IndexEntry,
					CE_NAMEMASK
				)

from util import 	(
					pack, 
					unpack
					)

from gitdb.base import IStream
from gitdb.typ import str_tree_type
from binascii import a2b_hex

__all__ = ('write_cache', 'read_cache', 'write_tree_from_cache', 'entry_key' )

def write_cache_entry(entry, stream):
	"""Write the given entry to the stream"""
	beginoffset = stream.tell()
	write = stream.write
	write(entry[4])			# ctime
	write(entry[5])			# mtime
	path = entry[3]
	plen = len(path) & CE_NAMEMASK		# path length
	assert plen == len(path), "Path %s too long to fit into index" % entry[3]
	flags = plen | entry[2]
	write(pack(">LLLLLL20sH", entry[6], entry[7], entry[0],
								entry[8], entry[9], entry[10], entry[1], flags))
	write(path)
	real_size = ((stream.tell() - beginoffset + 8) & ~7)
	write("\0" * ((beginoffset + real_size) - stream.tell()))

def write_cache(entries, stream, extension_data=None, ShaStreamCls=IndexFileSHA1Writer):
	"""Write the cache represented by entries to a stream
	:param entries: **sorted** list of entries
	:param stream: stream to wrap into the AdapterStreamCls - it is used for
		final output.
	:param ShaStreamCls: Type to use when writing to the stream. It produces a sha
		while writing to it, before the data is passed on to the wrapped stream
	:param extension_data: any kind of data to write as a trailer, it must begin
		a 4 byte identifier, followed by its size ( 4 bytes )"""
	# wrap the stream into a compatible writer
	stream = ShaStreamCls(stream)

	# header
	version = 2
	stream.write("DIRC")
	stream.write(pack(">LL", version, len(entries)))

	# body
	for entry in entries:
		write_cache_entry(entry, stream)
	# END for each entry

	# write previously cached extensions data
	if extension_data is not None:
		stream.write(extension_data)

	# write the sha over the content
	stream.write_sha()
	
def read_entry(stream):
	"""Return: One entry of the given stream"""
	beginoffset = stream.tell()
	ctime = unpack(">8s", stream.read(8))[0]
	mtime = unpack(">8s", stream.read(8))[0]
	(dev, ino, mode, uid, gid, size, sha, flags) = \
		unpack(">LLLLLL20sH", stream.read(20 + 4 * 6 + 2))
	path_size = flags & CE_NAMEMASK
	path = stream.read(path_size)

	real_size = ((stream.tell() - beginoffset + 8) & ~7)
	data = stream.read((beginoffset + real_size) - stream.tell())
	return IndexEntry((mode, sha, flags, path, ctime, mtime, dev, ino, uid, gid, size))

def read_header(stream):
		"""Return tuple(version_long, num_entries) from the given stream"""
		type_id = stream.read(4)
		if type_id != "DIRC":
			raise AssertionError("Invalid index file header: %r" % type_id)
		version, num_entries = unpack(">LL", stream.read(4 * 2))
		
		# TODO: handle version 3: extended data, see read-cache.c
		assert version in (1, 2)
		return version, num_entries

def entry_key(*entry):
	""":return: Key suitable to be used for the index.entries dictionary
	:param *entry: One instance of type BaseIndexEntry or the path and the stage"""
	if len(entry) == 1:
		return (entry[0].path, entry[0].stage)
	else:
		return tuple(entry)
	# END handle entry

def read_cache(stream):
	"""Read a cache file from the given stream
	:return: tuple(version, entries_dict, extension_data, content_sha)
		* version is the integer version number
		* entries dict is a dictionary which maps IndexEntry instances to a path
			at a stage
		* extension_data is '' or 4 bytes of type + 4 bytes of size + size bytes
		* content_sha is a 20 byte sha on all cache file contents"""
	version, num_entries = read_header(stream)
	count = 0
	entries = dict()
	while count < num_entries:
		entry = read_entry(stream)
		# entry_key would be the method to use, but we safe the effort
		entries[(entry.path, entry.stage)] = entry
		count += 1
	# END for each entry

	# the footer contains extension data and a sha on the content so far
	# Keep the extension footer,and verify we have a sha in the end
	# Extension data format is:
	# 4 bytes ID
	# 4 bytes length of chunk
	# repeated 0 - N times
	extension_data = stream.read(~0)
	assert len(extension_data) > 19, "Index Footer was not at least a sha on content as it was only %i bytes in size" % len(extension_data)

	content_sha = extension_data[-20:]

	# truncate the sha in the end as we will dynamically create it anyway
	extension_data = extension_data[:-20]
	
	return (version, entries, extension_data, content_sha)
	
def write_tree_from_cache(entries, odb, sl, si=0):
	"""Create a tree from the given sorted list of entries and put the respective
	trees into the given object database
	:param entries: **sorted** list of IndexEntries
	:param odb: object database to store the trees in
	:param si: start index at which we should start creating subtrees
	:param sl: slice indicating the range we should process on the entries list
	:return: tuple(binsha, list(tree_entry, ...)) a tuple of a sha and a list of 
		tree entries being a tuple of hexsha, mode, name"""
	tree_items = list()
	ci = sl.start
	end = sl.stop
	while ci < end:
		entry = entries[ci]
		if entry.stage != 0:
			raise UnmergedEntriesError(entry)
		# END abort on unmerged
		ci += 1
		rbound = entry.path.find('/', si)
		if rbound == -1:
			# its not a tree
			tree_items.append((entry.binsha, entry.mode, entry.path[si:]))
		else:
			# find common base range
			base = entry.path[si:rbound]
			xi = ci
			while xi < end:
				oentry = entries[xi]
				orbound = oentry.path.find('/', si)
				if orbound == -1 or oentry.path[si:orbound] != base:
					break
				# END abort on base mismatch
				xi += 1
			# END find common base
			
			# enter recursion
			# ci - 1 as we want to count our current item as well
			sha, tree_entry_list = write_tree_from_cache(entries, odb, slice(ci-1, xi), rbound+1)
			tree_items.append((sha, S_IFDIR, base))
			
			# skip ahead
			ci = xi
		# END handle bounds 
	# END for each entry
	
	# finally create the tree
	sio = StringIO()
	tree_to_stream(tree_items, sio.write)
	sio.seek(0)
	
	istream = odb.store(IStream(str_tree_type, len(sio.getvalue()), sio))
	return (istream.binsha, tree_items)
	
	
	
