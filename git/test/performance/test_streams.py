"""Performance data streaming performance"""
from git.db.py import *
from git.base import *
from git.stream import *
from git.util import (
							pool,
							bin_to_hex
						)

from git.test.lib import TestBase
from git import *
from git.util import bin_to_hex

from cStringIO import StringIO
from time import time
import os
import sys
import stat
import subprocess

from git.test.lib import make_memory_file

from lib import (
	TestBigRepoR
	make_memory_file,
	with_rw_directory
	)


#{ Utilities
def read_chunked_stream(stream):
	total = 0
	while True:
		chunk = stream.read(chunk_size)
		total += len(chunk)
		if len(chunk) < chunk_size:
			break
	# END read stream loop
	assert total == stream.size
	return stream
	
	
class TestStreamReader(ChannelThreadTask):
	"""Expects input streams and reads them in chunks. It will read one at a time, 
	requireing a queue chunk of size 1"""
	def __init__(self, *args):
		super(TestStreamReader, self).__init__(*args)
		self.fun = read_chunked_stream
		self.max_chunksize = 1
	

#} END utilities

class TestObjDBPerformance(TestBigRepoR):
	
	large_data_size_bytes = 1000*1000*10		# some MiB should do it
	moderate_data_size_bytes = 1000*1000*1		# just 1 MiB
	
	@with_rw_repo('HEAD', bare=True)
	def test_large_data_streaming(self, rwrepo):
		# TODO: This part overlaps with the same file in git.test.performance.test_stream
		# It should be shared if possible
		ldb = LooseObjectDB(os.path.join(rwrepo.git_dir, 'objects'))
		
		for randomize in range(2):
			desc = (randomize and 'random ') or ''
			print >> sys.stderr, "Creating %s data ..." % desc
			st = time()
			size, stream = make_memory_file(self.large_data_size_bytes, randomize)
			elapsed = time() - st
			print >> sys.stderr, "Done (in %f s)" % elapsed
			
			# writing - due to the compression it will seem faster than it is 
			st = time()
			binsha = ldb.store(IStream('blob', size, stream)).binsha
			elapsed_add = time() - st
			assert ldb.has_object(binsha)
			db_file = ldb.readable_db_object_path(bin_to_hex(binsha))
			fsize_kib = os.path.getsize(db_file) / 1000
			
			
			size_kib = size / 1000
			print >> sys.stderr, "Added %i KiB (filesize = %i KiB) of %s data to loose odb in %f s ( %f Write KiB / s)" % (size_kib, fsize_kib, desc, elapsed_add, size_kib / elapsed_add)
			
			# reading all at once
			st = time()
			ostream = ldb.stream(binsha)
			shadata = ostream.read()
			elapsed_readall = time() - st
			
			stream.seek(0)
			assert shadata == stream.getvalue()
			print >> sys.stderr, "Read %i KiB of %s data at once from loose odb in %f s ( %f Read KiB / s)" % (size_kib, desc, elapsed_readall, size_kib / elapsed_readall)
			
			
			# reading in chunks of 1 MiB
			cs = 512*1000
			chunks = list()
			st = time()
			ostream = ldb.stream(binsha)
			while True:
				data = ostream.read(cs)
				chunks.append(data)
				if len(data) < cs:
					break
			# END read in chunks
			elapsed_readchunks = time() - st
			
			stream.seek(0)
			assert ''.join(chunks) == stream.getvalue()
			
			cs_kib = cs / 1000
			print >> sys.stderr, "Read %i KiB of %s data in %i KiB chunks from loose odb in %f s ( %f Read KiB / s)" % (size_kib, desc, cs_kib, elapsed_readchunks, size_kib / elapsed_readchunks)
			
			# del db file so git has something to do
			os.remove(db_file)
			
			# VS. CGIT 
			##########
			# CGIT ! Can using the cgit programs be faster ?
			proc = rwrepo.git.hash_object('-w', '--stdin', as_process=True, istream=subprocess.PIPE)
			
			# write file - pump everything in at once to be a fast as possible
			data = stream.getvalue()	# cache it
			st = time()
			proc.stdin.write(data)
			proc.stdin.close()
			gitsha = proc.stdout.read().strip()
			proc.wait()
			gelapsed_add = time() - st
			del(data)
			assert gitsha == bin_to_hex(binsha)		# we do it the same way, right ?
			
			#  as its the same sha, we reuse our path
			fsize_kib = os.path.getsize(db_file) / 1000
			print >> sys.stderr, "Added %i KiB (filesize = %i KiB) of %s data to using git-hash-object in %f s ( %f Write KiB / s)" % (size_kib, fsize_kib, desc, gelapsed_add, size_kib / gelapsed_add)
			
			# compare ... 
			print >> sys.stderr, "Git-Python is %f %% faster than git when adding big %s files" % (100.0 - (elapsed_add / gelapsed_add) * 100, desc)
			
			
			# read all
			st = time()
			s, t, size, data = rwrepo.git.get_object_data(gitsha)
			gelapsed_readall = time() - st
			print >> sys.stderr, "Read %i KiB of %s data at once using git-cat-file in %f s ( %f Read KiB / s)" % (size_kib, desc, gelapsed_readall, size_kib / gelapsed_readall)

			# compare 
			print >> sys.stderr, "Git-Python is %f %% faster than git when reading big %sfiles" % (100.0 - (elapsed_readall / gelapsed_readall) * 100, desc)
			
			
			# read chunks
			st = time()
			s, t, size, stream = rwrepo.git.stream_object_data(gitsha)
			while True:
				data = stream.read(cs)
				if len(data) < cs:
					break
			# END read stream
			gelapsed_readchunks = time() - st
			print >> sys.stderr, "Read %i KiB of %s data in %i KiB chunks from git-cat-file in %f s ( %f Read KiB / s)" % (size_kib, desc, cs_kib, gelapsed_readchunks, size_kib / gelapsed_readchunks)
			
			# compare 
			print >> sys.stderr, "Git-Python is %f %% faster than git when reading big %s files in chunks" % (100.0 - (elapsed_readchunks / gelapsed_readchunks) * 100, desc)
		# END for each randomization factor
		
	@with_rw_directory
	def test_large_data_streaming(self, path):
		ldb = PureLooseObjectODB(path)
		string_ios = list()			# list of streams we previously created
		
		# serial mode 
		for randomize in range(2):
			desc = (randomize and 'random ') or ''
			print >> sys.stderr, "Creating %s data ..." % desc
			st = time()
			size, stream = make_memory_file(self.large_data_size_bytes, randomize)
			elapsed = time() - st
			print >> sys.stderr, "Done (in %f s)" % elapsed
			string_ios.append(stream)
			
			# writing - due to the compression it will seem faster than it is 
			st = time()
			sha = ldb.store(IStream('blob', size, stream)).binsha
			elapsed_add = time() - st
			assert ldb.has_object(sha)
			db_file = ldb.readable_db_object_path(bin_to_hex(sha))
			fsize_kib = os.path.getsize(db_file) / 1000
			
			
			size_kib = size / 1000
			print >> sys.stderr, "Added %i KiB (filesize = %i KiB) of %s data to loose odb in %f s ( %f Write KiB / s)" % (size_kib, fsize_kib, desc, elapsed_add, size_kib / elapsed_add)
			
			# reading all at once
			st = time()
			ostream = ldb.stream(sha)
			shadata = ostream.read()
			elapsed_readall = time() - st
			
			stream.seek(0)
			assert shadata == stream.getvalue()
			print >> sys.stderr, "Read %i KiB of %s data at once from loose odb in %f s ( %f Read KiB / s)" % (size_kib, desc, elapsed_readall, size_kib / elapsed_readall)
			
			
			# reading in chunks of 1 MiB
			cs = 512*1000
			chunks = list()
			st = time()
			ostream = ldb.stream(sha)
			while True:
				data = ostream.read(cs)
				chunks.append(data)
				if len(data) < cs:
					break
			# END read in chunks
			elapsed_readchunks = time() - st
			
			stream.seek(0)
			assert ''.join(chunks) == stream.getvalue()
			
			cs_kib = cs / 1000
			print >> sys.stderr, "Read %i KiB of %s data in %i KiB chunks from loose odb in %f s ( %f Read KiB / s)" % (size_kib, desc, cs_kib, elapsed_readchunks, size_kib / elapsed_readchunks)
			
			# del db file so we keep something to do
			os.remove(db_file)
		# END for each randomization factor
		
		
		# multi-threaded mode
		# want two, should be supported by most of todays cpus
		pool.set_size(2)
		total_kib = 0
		nsios = len(string_ios)
		for stream in string_ios:
			stream.seek(0)
			total_kib += len(stream.getvalue()) / 1000
		# END rewind
		
		def istream_iter():
			for stream in string_ios:
				stream.seek(0)
				yield IStream(str_blob_type, len(stream.getvalue()), stream)
			# END for each stream
		# END util
		
		# write multiple objects at once, involving concurrent compression
		reader = IteratorReader(istream_iter())
		istream_reader = ldb.store_async(reader)
		istream_reader.task().max_chunksize = 1
		
		st = time()
		istreams = istream_reader.read(nsios)
		assert len(istreams) == nsios
		elapsed = time() - st
		
		print >> sys.stderr, "Threads(%i): Compressed %i KiB of data in loose odb in %f s ( %f Write KiB / s)" % (pool.size(), total_kib, elapsed, total_kib / elapsed)
		
		# decompress multiple at once, by reading them
		# chunk size is not important as the stream will not really be decompressed
		
		# until its read
		istream_reader = IteratorReader(iter([ i.binsha for i in istreams ]))
		ostream_reader = ldb.stream_async(istream_reader)
		
		chunk_task = TestStreamReader(ostream_reader, "chunker", None)
		output_reader = pool.add_task(chunk_task)
		output_reader.task().max_chunksize = 1
		
		st = time()
		assert len(output_reader.read(nsios)) == nsios
		elapsed = time() - st
		
		print >> sys.stderr, "Threads(%i): Decompressed %i KiB of data in loose odb in %f s ( %f Read KiB / s)" % (pool.size(), total_kib, elapsed, total_kib / elapsed)
		
		# store the files, and read them back. For the reading, we use a task 
		# as well which is chunked into one item per task. Reading all will
		# very quickly result in two threads handling two bytestreams of 
		# chained compression/decompression streams
		reader = IteratorReader(istream_iter())
		istream_reader = ldb.store_async(reader)
		istream_reader.task().max_chunksize = 1
		
		istream_to_sha = lambda items: [ i.binsha for i in items ]
		istream_reader.set_post_cb(istream_to_sha)
		
		ostream_reader = ldb.stream_async(istream_reader)
		
		chunk_task = TestStreamReader(ostream_reader, "chunker", None)
		output_reader = pool.add_task(chunk_task)
		output_reader.max_chunksize = 1
		
		st = time()
		assert len(output_reader.read(nsios)) == nsios
		elapsed = time() - st
		
		print >> sys.stderr, "Threads(%i): Compressed and decompressed and read %i KiB of data in loose odb in %f s ( %f Combined KiB / s)" % (pool.size(), total_kib, elapsed, total_kib / elapsed)
