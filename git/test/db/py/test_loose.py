# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.test.db.lib import TestDBBase, with_rw_directory
from git.db.py.loose import PureLooseObjectODB
from git.exc import BadObject
from git.util import bin_to_hex
		
class TestLooseDB(TestDBBase):
	
	needs_ro_repo = False
	
	@with_rw_directory
	def test_basics(self, path):
		ldb = PureLooseObjectODB(path)
		
		# write data
		self._assert_object_writing(ldb)
		self._assert_object_writing_async(ldb)
	
		# verify sha iteration and size
		shas = list(ldb.sha_iter())
		assert shas and len(shas[0]) == 20
		
		assert len(shas) == ldb.size()
		
		# verify find short object
		long_sha = bin_to_hex(shas[-1])
		for short_sha in (long_sha[:20], long_sha[:5]):
			assert bin_to_hex(ldb.partial_to_complete_sha_hex(short_sha)) == long_sha
		# END for each sha
		
		self.failUnlessRaises(BadObject, ldb.partial_to_complete_sha_hex, '0000')
		# raises if no object could be foudn
		
