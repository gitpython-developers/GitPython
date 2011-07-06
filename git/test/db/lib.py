# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""Base classes for object db testing"""
from git.test.lib import (
	with_rw_directory,
	with_packs_rw,
	ZippedStoreShaWriter,
	fixture_path,
	TestBase,
	rorepo_dir,
	)

from git.stream import Sha1Writer
from git.base import (
							IStream,
							OStream,
							OInfo
						)
				
from git.exc import BadObject
from git.typ import str_blob_type

from async import IteratorReader
from cStringIO import StringIO
from struct import pack


__all__ = ('TestDBBase', 'with_rw_directory', 'with_packs_rw', 'fixture_path')
		
class TestDBBase(TestBase):
	"""Base Class providing default functionality to all tests such as:
	
	- Utility functions provided by the TestCase base of the unittest method such as::
		self.fail("todo")
		self.failUnlessRaises(...)
		
	- Class level repository which is considered read-only as it is shared among 
	  all test cases in your type.
	  Access it using:: 
	   self.rorepo	# 'ro' stands for read-only
	   
	  The rorepo is in fact your current project's git repo. If you refer to specific 
	  shas for your objects, be sure you choose some that are part of the immutable portion 
	  of the project history ( to assure tests don't fail for others ).
	  
	  Derived types can override the default repository type to create a different
	  read-only repo, allowing to test their specific type
	"""
	
	# data
	two_lines = "1234\nhello world"
	all_data = (two_lines, )
	
	#{ Configuration
	# The repository type to instantiate. It takes at least a path to operate upon
	# during instantiation.
	RepoCls = None
	
	# if True, a read-only repo will be provided and RepoCls must be set.
	# Otherwise it may remain unset
	needs_ro_repo = True
	#} END configuration
	
	@classmethod
	def setUpAll(cls):
		"""
		Dynamically add a read-only repository to our actual type. This way 
		each test type has its own repository
		"""
		if cls.needs_ro_repo:
			if cls is not TestDBBase:
				assert cls.RepoCls is not None, "RepoCls class member must be set in %s" % cls
			cls.rorepo = cls.RepoCls(rorepo_dir())
		#END handle rorepo
	
	def _assert_object_writing_simple(self, db):
		# write a bunch of objects and query their streams and info
		null_objs = db.size()
		ni = 250
		for i in xrange(ni):
			data = pack(">L", i)
			istream = IStream(str_blob_type, len(data), StringIO(data))
			new_istream = db.store(istream)
			assert new_istream is istream
			assert db.has_object(istream.binsha)
			
			info = db.info(istream.binsha)
			assert isinstance(info, OInfo)
			assert info.type == istream.type and info.size == istream.size
			
			stream = db.stream(istream.binsha)
			assert isinstance(stream, OStream)
			assert stream.binsha == info.binsha and stream.type == info.type
			assert stream.read() == data
		# END for each item
		
		assert db.size() == null_objs + ni
		shas = list(db.sha_iter())
		assert len(shas) == db.size()
		assert len(shas[0]) == 20
		
	
	def _assert_object_writing(self, db):
		"""General tests to verify object writing, compatible to ObjectDBW
		:note: requires write access to the database"""
		# start in 'dry-run' mode, using a simple sha1 writer
		ostreams = (ZippedStoreShaWriter, None)
		for ostreamcls in ostreams:
			for data in self.all_data:
				dry_run = ostreamcls is not None
				ostream = None
				if ostreamcls is not None:
					ostream = ostreamcls()
					assert isinstance(ostream, Sha1Writer)
				# END create ostream
				
				prev_ostream = db.set_ostream(ostream)
				assert type(prev_ostream) in ostreams or prev_ostream in ostreams 
					
				istream = IStream(str_blob_type, len(data), StringIO(data))
				
				# store returns same istream instance, with new sha set
				my_istream = db.store(istream)
				sha = istream.binsha
				assert my_istream is istream
				assert db.has_object(sha) != dry_run
				assert len(sha) == 20	
				
				# verify data - the slow way, we want to run code
				if not dry_run:
					info = db.info(sha)
					assert str_blob_type == info.type
					assert info.size == len(data)
					
					ostream = db.stream(sha)
					assert ostream.read() == data
					assert ostream.type == str_blob_type
					assert ostream.size == len(data)
				else:
					self.failUnlessRaises(BadObject, db.info, sha)
					self.failUnlessRaises(BadObject, db.stream, sha)
					
					# DIRECT STREAM COPY
					# our data hase been written in object format to the StringIO
					# we pasesd as output stream. No physical database representation
					# was created.
					# Test direct stream copy of object streams, the result must be 
					# identical to what we fed in
					ostream.seek(0)
					istream.stream = ostream
					assert istream.binsha is not None
					prev_sha = istream.binsha
					
					db.set_ostream(ZippedStoreShaWriter())
					db.store(istream)
					assert istream.binsha == prev_sha
					new_ostream = db.ostream()
					
					# note: only works as long our store write uses the same compression
					# level, which is zip_best
					assert ostream.getvalue() == new_ostream.getvalue()
			# END for each data set
		# END for each dry_run mode
		
	def _assert_object_writing_async(self, db):
		"""Test generic object writing using asynchronous access"""
		ni = 5000
		def istream_generator(offset=0, ni=ni):
			for data_src in xrange(ni):
				data = str(data_src + offset)
				yield IStream(str_blob_type, len(data), StringIO(data))
			# END for each item
		# END generator utility
		
		# for now, we are very trusty here as we expect it to work if it worked
		# in the single-stream case
		
		# write objects
		reader = IteratorReader(istream_generator())
		istream_reader = db.store_async(reader)
		istreams = istream_reader.read()		# read all
		assert istream_reader.task().error() is None
		assert len(istreams) == ni
		
		for stream in istreams:
			assert stream.error is None
			assert len(stream.binsha) == 20
			assert isinstance(stream, IStream)
		# END assert each stream
		
		# test has-object-async - we must have all previously added ones
		reader = IteratorReader( istream.binsha for istream in istreams )
		hasobject_reader = db.has_object_async(reader)
		count = 0
		for sha, has_object in hasobject_reader:
			assert has_object
			count += 1
		# END for each sha
		assert count == ni
		
		# read the objects we have just written
		reader = IteratorReader( istream.binsha for istream in istreams )
		ostream_reader = db.stream_async(reader)
		
		# read items individually to prevent hitting possible sys-limits
		count = 0
		for ostream in ostream_reader:
			assert isinstance(ostream, OStream)
			count += 1
		# END for each ostream
		assert ostream_reader.task().error() is None
		assert count == ni
		
		# get info about our items
		reader = IteratorReader( istream.binsha for istream in istreams )
		info_reader = db.info_async(reader)
		
		count = 0
		for oinfo in info_reader:
			assert isinstance(oinfo, OInfo)
			count += 1
		# END for each oinfo instance
		assert count == ni
		
		  
		# combined read-write using a converter
		# add 2500 items, and obtain their output streams
		nni = 2500
		reader = IteratorReader(istream_generator(offset=ni, ni=nni))
		istream_to_sha = lambda istreams: [ istream.binsha for istream in istreams ]
		
		istream_reader = db.store_async(reader)
		istream_reader.set_post_cb(istream_to_sha)
		
		ostream_reader = db.stream_async(istream_reader)
		
		count = 0
		# read it individually, otherwise we might run into the ulimit
		for ostream in ostream_reader:
			assert isinstance(ostream, OStream)
			count += 1
		# END for each ostream
		assert count == nni
		
		
