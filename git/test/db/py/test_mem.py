# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from lib import *
from git.db.py import (
						PureMemoryDB,
						PureLooseObjectODB
					)
		
class TestPureMemoryDB(TestDBBase):
	
	@with_rw_directory
	def test_writing(self, path):
		mdb = PureMemoryDB()
		
		# write data
		self._assert_object_writing_simple(mdb)
		
		# test stream copy
		ldb = PureLooseObjectODB(path)
		assert ldb.size() == 0
		num_streams_copied = mdb.stream_copy(mdb.sha_iter(), ldb)
		assert num_streams_copied == mdb.size()
		
		assert ldb.size() == mdb.size()
		for sha in mdb.sha_iter():
			assert ldb.has_object(sha)
			assert ldb.stream(sha).read() == mdb.stream(sha).read() 
		# END verify objects where copied and are equal
