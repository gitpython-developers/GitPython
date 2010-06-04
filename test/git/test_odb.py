"""Test for object db"""

from test.testlib import *
from git.odb import *
from git.odb.stream import Sha1Writer
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
		"""General tests to verify object writing, compatible to ObjectDBW
		:note: requires write access to the database"""
		# start in 'dry-run' mode, using a simple sha1 writer
		ostreams = (Sha1Writer, None)
		for ostreamcls in ostreams:
			for data in self.all_data:
				dry_run = ostreamcls is not None
				ostream = None
				if ostreamcls is not None:
					ostream = ostreamcls()
				# END create ostream
				
				prev_ostream = db.set_ostream(ostream)
				assert type(prev_ostream) in ostreams or prev_ostream in ostreams 
					
				istream = IStream(Blob.type, len(data), StringIO(data))
				my_istream = db.store(istream)
				sha = istream.sha
				assert my_istream is istream
				assert db.has_object(sha) != dry_run
				assert len(sha) == 40		# for now we require 40 byte shas as default
				
				# verify data - the slow way, we want to run code
				if not dry_run:
					info = db.info(sha)
					assert Blob.type == info.type
					assert info.size == len(data)
					
					ostream = db.stream(sha)
					assert ostream.read() == data
					assert ostream.type == Blob.type
					assert ostream.size == len(data)
				else:
					self.failUnlessRaises(BadObject, db.info, sha)
					self.failUnlessRaises(BadObject, db.stream, sha)
			# END for each data set
		# END for each dry_run mode
				
	@with_bare_rw_repo
	def test_writing(self, rwrepo):
		ldb = LooseObjectDB(os.path.join(rwrepo.git_dir, 'objects'))
		
		# write data
		self._assert_object_writing(ldb)
	
