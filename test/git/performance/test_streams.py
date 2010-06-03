"""Performance data streaming performance"""

from test.testlib import *
from git.odb.db import *

from array import array
from cStringIO import StringIO
from time import time
import os
import sys
import stat
import random


from lib import (
	TestBigRepoReadOnly
	)



def make_memory_file(size_in_bytes, randomize=False):
	""":return: tuple(size_of_stream, stream)
	:param randomize: try to produce a very random stream"""
	actual_size = size_in_bytes / 4
	producer = xrange(actual_size)
	if randomize:
		producer = list(producer)
		random.shuffle(producer)
	# END randomize
	a = array('i', producer)
	return actual_size*4, StringIO(a.tostring())


class TestObjDBPerformance(TestBigRepoReadOnly):
	
	large_data_size_bytes = 1000*1000*10		# some MiB should do it
	moderate_data_size_bytes = 1000*1000*1		# just 1 MiB
	
	@with_bare_rw_repo
	def test_large_data_streaming(self, rwrepo):
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
			sha = ldb.to_object('blob', size, stream)
			elapsed = time() - st
			assert ldb.has_object(sha)
			fsize_kib = os.path.getsize(ldb.readable_db_object_path(sha)) / 1000
			
			
			size_kib = size / 1000
			print >> sys.stderr, "Added %i KiB (filesize = %i KiB) of %s data to loose odb in %f s ( %f Write KiB / s)" % (size_kib, fsize_kib, desc, elapsed, size_kib / elapsed)
			
			# reading all at once
			st = time()
			type, size, shastream = ldb.object(sha)
			shadata = shastream.read()
			elapsed = time() - st
			
			stream.seek(0)
			assert shadata == stream.getvalue()
			print >> sys.stderr, "Read %i KiB of %s data at once from loose odb in %f s ( %f Read KiB / s)" % (size_kib, desc, elapsed, size_kib / elapsed)
			
			
			# reading in chunks of 1 MiB
			cs = 512*1000
			chunks = list()
			st = time()
			type, size, shastream = ldb.object(sha)
			while True:
				data = shastream.read(cs)
				chunks.append(data)
				if len(data) < cs:
					break
			# END read in chunks
			elapsed = time() - st
			
			stream.seek(0)
			assert ''.join(chunks) == stream.getvalue()
			
			cs_kib = cs / 1000
			print >> sys.stderr, "Read %i KiB of %s data in %i KiB chunks from loose odb in %f s ( %f Read KiB / s)" % (size_kib, desc, cs_kib, elapsed, size_kib / elapsed)
		# END for each randomization factor
