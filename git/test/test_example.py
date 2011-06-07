# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Module with examples from the tutorial section of the docs"""
from lib import TestBase, fixture_path
from git.base import IStream
from git.db.py.loose import PureLooseObjectODB
from git.util import pool
		
from cStringIO import StringIO

from async import IteratorReader
		
class TestExamples(TestBase):
	
	def test_base(self):
		ldb = PureLooseObjectODB(fixture_path("../../../.git/objects"))
		
		for sha1 in ldb.sha_iter():
			oinfo = ldb.info(sha1)
			ostream = ldb.stream(sha1)
			assert oinfo[:3] == ostream[:3]
			
			assert len(ostream.read()) == ostream.size
			assert ldb.has_object(oinfo.binsha)
		# END for each sha in database
		# assure we close all files
		try:
			del(ostream)
			del(oinfo)
		except UnboundLocalError:
			pass
		# END ignore exception if there are no loose objects
			
		data = "my data"
		istream = IStream("blob", len(data), StringIO(data))
		
		# the object does not yet have a sha
		assert istream.binsha is None
		ldb.store(istream)
		# now the sha is set
		assert len(istream.binsha) == 20
		assert ldb.has_object(istream.binsha)
		
		
		# async operation
		# Create a reader from an iterator
		reader = IteratorReader(ldb.sha_iter())
		
		# get reader for object streams
		info_reader = ldb.stream_async(reader)
		
		# read one
		info = info_reader.read(1)[0]
		
		# read all the rest until depletion
		ostreams = info_reader.read()
		
		# set the pool to use two threads
		pool.set_size(2)
		
		# synchronize the mode of operation
		pool.set_size(0)
