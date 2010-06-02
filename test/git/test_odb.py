"""Test for object db"""

from test.testlib import *
from git.odb.db import *
from git import Blob
from git.errors import BadObject

from cStringIO import StringIO
import os


class TestDB(TestBase):
	"""Test the different db class implementations"""
	
	# data
	two_lines = "1234\nhello world"
	
	all_data = (two_lines, )
	
	def _assert_object_writing(self, db):
		"""General tests to verify object writing, compatible to iObjectDBW
		:note: requires write access to the database"""
		# start in dry-run mode
		for dry_run in range(1, -1, -1):
			for data in self.all_data:
				for hex_sha in range(2):
					sha = db.to_object(Blob.type, len(data), StringIO(data), dry_run, hex_sha)
					assert db.has_object(sha) != dry_run
					assert len(sha) == 20 + hex_sha * 20
					
					# verify data - the slow way, we want to run code
					if not dry_run:
						type, size = db.object_info(sha)
						assert Blob.type == type
						assert size == len(data)
						
						type, size, stream = db.object(sha)
						assert stream.read() == data
					else:
						self.failUnlessRaises(BadObject, db.object_info, sha)
						self.failUnlessRaises(BadObject, db.object, sha)
				# END for each sha type
			# END for each data set
		# END for each dry_run mode
				
	@with_bare_rw_repo
	def test_writing(self, rwrepo):
		ldb = LooseObjectDB(os.path.join(rwrepo.git_dir, 'objects'))
		
		# write data
		self._assert_object_writing(ldb)
	
