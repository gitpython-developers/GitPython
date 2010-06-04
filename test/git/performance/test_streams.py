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
import subprocess


from lib import (
	TestBigRepoR
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


class TestObjDBPerformance(TestBigRepoR):
	
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
			sha = ldb.store('blob', size, stream)
			elapsed_add = time() - st
			assert ldb.has_object(sha)
			db_file = ldb.readable_db_object_path(sha)
			fsize_kib = os.path.getsize(db_file) / 1000
			
			
			size_kib = size / 1000
			print >> sys.stderr, "Added %i KiB (filesize = %i KiB) of %s data to loose odb in %f s ( %f Write KiB / s)" % (size_kib, fsize_kib, desc, elapsed_add, size_kib / elapsed_add)
			
			# reading all at once
			st = time()
			type, size, shastream = ldbstreamsha)
			shadata = shastream.read()
			elapsed_readall = time() - st
			
			stream.seek(0)
			assert shadata == stream.getvalue()
			print >> sys.stderr, "Read %i KiB of %s data at once from loose odb in %f s ( %f Read KiB / s)" % (size_kib, desc, elapsed_readall, size_kib / elapsed_readall)
			
			
			# reading in chunks of 1 MiB
			cs = 512*1000
			chunks = list()
			st = time()
			type, size, shastream = ldbstreamsha)
			while True:
				data = shastream.read(cs)
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
			assert gitsha == sha		# we do it the same way, right ?
			
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
