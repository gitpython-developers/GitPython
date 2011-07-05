# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from packedodb_impl import TestPurePackedODBPerformanceBase
from git.db.py.pack import PurePackedODB

from git.stream import NullStream

from git.pack import PackEntity

import os
import sys

from time import time
from nose import SkipTest


class CountedNullStream(NullStream):
	__slots__ = '_bw'
	def __init__(self):
		self._bw = 0
		
	def bytes_written(self):
		return self._bw
		
	def write(self, d):
		self._bw += NullStream.write(self, d)
	

class TestPurePackedODB(TestPurePackedODBPerformanceBase):
	#{ Configuration
	PackedODBCls = PurePackedODB
	#} END configuration
	
	def test_pack_writing_note(self):
		sys.stderr.write("test_pack_writing should be adjusted to support different databases to read from - see test for more info")
		raise SkipTest()
	
	def test_pack_writing(self):
		# see how fast we can write a pack from object streams.
		# This will not be fast, as we take time for decompressing the streams as well
		# For now we test the fast streaming and slow streaming versions manually
		ostream = CountedNullStream()
		# NOTE: We use the same repo twice to see whether OS caching helps
		for rorepo in (self.rorepo, self.rorepo, self.ropdb):
			
			ni = 5000
			count = 0
			total_size = 0
			st = time()
			for sha in rorepo.sha_iter():
				count += 1
				rorepo.stream(sha)
				if count == ni:
					break
			#END gather objects for pack-writing
			elapsed = time() - st
			print >> sys.stderr, "PDB Streaming: Got %i streams from %s by sha in in %f s ( %f streams/s )" % (count, rorepo.__class__.__name__, elapsed, count / elapsed)
			
			st = time()
			PackEntity.write_pack((rorepo.stream(sha) for sha in rorepo.sha_iter()), ostream.write, object_count=ni)
			elapsed = time() - st
			total_kb = ostream.bytes_written() / 1000
			print >> sys.stderr, "PDB Streaming: Wrote pack of size %i kb in %f s (%f kb/s)" % (total_kb, elapsed, total_kb/elapsed)
		#END for each rorepo
		
	
	def test_stream_reading(self):
		raise SkipTest("This test was only used for --with-profile runs")
		pdb = self.ropdb
		
		# streaming only, meant for --with-profile runs
		ni = 5000
		count = 0
		pdb_stream = pdb.stream
		total_size = 0
		st = time()
		for sha in pdb.sha_iter():
			if count == ni:
				break
			stream = pdb_stream(sha)
			stream.read()
			total_size += stream.size
			count += 1
		elapsed = time() - st
		total_kib = total_size / 1000
		print >> sys.stderr, "PDB Streaming: Got %i streams by sha and read all bytes totallying %i KiB ( %f KiB / s ) in %f s ( %f streams/s )" % (ni, total_kib, total_kib/elapsed , elapsed, ni / elapsed)
		
