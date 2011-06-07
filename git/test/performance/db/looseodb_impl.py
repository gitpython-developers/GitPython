"""Performance data streaming performance"""
from git.db.py import *
from git.base import *
from git.stream import *
from async import ChannelThreadTask
from git.util import (
							pool,
							bin_to_hex
						)
import os
import sys
from time import time

from git.test.lib import (
	GlobalsItemDeletorMetaCls,
	make_memory_file,
	with_rw_repo
	)

from git.test.performance.lib import TestBigRepoR


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

class PerfBaseDeletorMetaClass(GlobalsItemDeletorMetaCls):
	ModuleToDelete = 'TestLooseDBWPerformanceBase'


class TestLooseDBWPerformanceBase(TestBigRepoR):
	__metaclass__ = PerfBaseDeletorMetaClass
	
	large_data_size_bytes = 1000*1000*10		# some MiB should do it
	moderate_data_size_bytes = 1000*1000*1		# just 1 MiB
	
	#{ Configuration
	LooseODBCls = None
	#} END configuration
	
	@classmethod
	def setUpAll(cls):
		super(TestLooseDBWPerformanceBase, cls).setUpAll()
		if cls.LooseODBCls is None:
			raise AssertionError("LooseODBCls must be set in subtype")
		#END assert configuration
		# currently there is no additional configuration
		
	@with_rw_repo("HEAD")
	def test_large_data_streaming(self, rwrepo):
		# TODO: This part overlaps with the same file in git.test.performance.test_stream
		# It should be shared if possible
		objects_path = rwrepo.db_path('')
		ldb = self.LooseODBCls(objects_path)
		
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
			hexsha = bin_to_hex(binsha)
			db_file = os.path.join(objects_path, hexsha[:2], hexsha[2:])
			fsize_kib = os.path.getsize(db_file) / 1000
			
			
			size_kib = size / 1000
			print >> sys.stderr, "%s: Added %i KiB (filesize = %i KiB) of %s data to loose odb in %f s ( %f Write KiB / s)" % (self.LooseODBCls.__name__, size_kib, fsize_kib, desc, elapsed_add, size_kib / elapsed_add)
			
			# reading all at once
			st = time()
			ostream = ldb.stream(binsha)
			shadata = ostream.read()
			elapsed_readall = time() - st
			
			stream.seek(0)
			assert shadata == stream.getvalue()
			print >> sys.stderr, "%s: Read %i KiB of %s data at once from loose odb in %f s ( %f Read KiB / s)" % (self.LooseODBCls.__name__, size_kib, desc, elapsed_readall, size_kib / elapsed_readall)
			
			
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
			print >> sys.stderr, "%s: Read %i KiB of %s data in %i KiB chunks from loose odb in %f s ( %f Read KiB / s)" % (self.LooseODBCls.__name__, size_kib, desc, cs_kib, elapsed_readchunks, size_kib / elapsed_readchunks)
			
			# del db file so git has something to do
			os.remove(db_file)
		# END for each randomization factor
		

