"""Test for object db"""
from test.testlib import *
from git.odb import *
from git.odb.utils import (
	to_hex_sha, 
	to_bin_sha
	)
from git.odb.stream import Sha1Writer
from git import Blob
from git.errors import BadObject
from cStringIO import StringIO
import tempfile
import os
import zlib


#{ Stream Utilities

class DummyStream(object):
		def __init__(self):
			self.was_read = False
			self.bytes = 0
			self.closed = False
			
		def read(self, size):
			self.was_read = True
			self.bytes = size
			
		def close(self):
			self.closed = True
			
		def _assert(self):
			assert self.was_read


class DeriveTest(OStream):
	def __init__(self, sha, type, size, stream, *args, **kwargs):
		self.myarg = kwargs.pop('myarg')
		self.args = args
		
	def _assert(self):
		assert self.args
		assert self.myarg


class ZippedStoreShaWriter(Sha1Writer):
	"""Remembers everything someone writes to it"""
	__slots__ = ('buf', 'zip')
	def __init__(self):
		Sha1Writer.__init__(self)
		self.buf = StringIO()
		self.zip = zlib.compressobj(1)	# fastest
	
	def __getattr__(self, attr):
		return getattr(self.buf, attr)
	
	def write(self, data):
		alen = Sha1Writer.write(self, data)
		self.buf.write(self.zip.compress(data))
		return alen
		
	def close(self):
		self.buf.write(self.zip.flush())


#} END stream utilitiess
	
	

class TestStream(TestBase):
	"""Test stream classes"""
	
	data_sizes = (15, 10000, 1000*1024+512)
	
	def test_streams(self):
		# test info
		sha = Blob.NULL_HEX_SHA
		s = 20
		info = OInfo(sha, Blob.type, s)
		assert info.sha == sha
		assert info.type == Blob.type
		assert info.size == s
		
		# test ostream
		stream = DummyStream()
		ostream = OStream(*(info + (stream, )))
		ostream.read(15)
		stream._assert()
		assert stream.bytes == 15
		ostream.read(20)
		assert stream.bytes == 20
		
		# derive with own args
		DeriveTest(sha, Blob.type, s, stream, 'mine',myarg = 3)._assert()
		
		# test istream
		istream = IStream(Blob.type, s, stream)
		assert istream.sha == None
		istream.sha = sha
		assert istream.sha == sha
		
		assert len(istream.binsha) == 20
		assert len(istream.hexsha) == 40
		
		assert istream.size == s
		istream.size = s * 2
		istream.size == s * 2
		assert istream.type == Blob.type
		istream.type = "something"
		assert istream.type == "something"
		assert istream.stream is stream
		istream.stream = None
		assert istream.stream is None
		
		assert istream.error is None
		istream.error = Exception()
		assert isinstance(istream.error, Exception)
		
	def _assert_stream_reader(self, stream, cdata, rewind_stream=lambda s: None):
		"""Make stream tests - the orig_stream is seekable, allowing it to be 
		rewound and reused
		:param cdata: the data we expect to read from stream, the contents
		:param rewind_stream: function called to rewind the stream to make it ready
			for reuse"""
		ns = 10
		assert len(cdata) > ns-1, "Data must be larger than %i, was %i" % (ns, len(cdata))
		
		# read in small steps
		ss = len(cdata) / ns
		for i in range(ns):
			data = stream.read(ss)
			chunk = cdata[i*ss:(i+1)*ss]
			assert data == chunk
		# END for each step
		rest = stream.read()
		if rest:
			assert rest == cdata[-len(rest):]
		# END handle rest
		
		rewind_stream(stream)
		
		# read everything
		rdata = stream.read()
		assert rdata == cdata
		
	def test_decompress_reader(self):
		for close_on_deletion in range(2):
			for with_size in range(2):
				for ds in self.data_sizes:
					cdata = make_bytes(ds, randomize=False)
					
					# zdata = zipped actual data
					# cdata = original content data
					
					# create reader
					if with_size:
						# need object data
						zdata = zlib.compress(make_object(Blob.type, cdata))
						type, size, reader = DecompressMemMapReader.new(zdata, close_on_deletion)
						assert size == len(cdata)
						assert type == Blob.type
					else:
						# here we need content data
						zdata = zlib.compress(cdata)
						reader = DecompressMemMapReader(zdata, close_on_deletion, len(cdata))
						assert reader._s == len(cdata)
					# END get reader 
					
					def rewind(r):
						r._zip = zlib.decompressobj()
						r._br = r._cws = r._cwe = 0
						if with_size:
							r._parse_header_info()
						# END skip header
					# END make rewind func
					
					self._assert_stream_reader(reader, cdata, rewind)
					
					# put in a dummy stream for closing
					dummy = DummyStream()
					reader._m = dummy
					
					assert not dummy.closed
					del(reader)
					assert dummy.closed == close_on_deletion
					#zdi#
				# END for each datasize
			# END whether size should be used
		# END whether stream should be closed when deleted
		
	def test_sha_writer(self):
		writer = Sha1Writer()
		assert 2 == writer.write("hi")
		assert len(writer.sha(as_hex=1)) == 40
		assert len(writer.sha(as_hex=0)) == 20
		
		# make sure it does something ;)
		prev_sha = writer.sha()
		writer.write("hi again")
		assert writer.sha() != prev_sha
		
	def test_compressed_writer(self):
		for ds in self.data_sizes:
			fd, path = tempfile.mkstemp()
			ostream = FDCompressedSha1Writer(fd)
			data = make_bytes(ds, randomize=False)
			
			# for now, just a single write, code doesn't care about chunking
			assert len(data) == ostream.write(data)
			ostream.close()
			# its closed already
			self.failUnlessRaises(OSError, os.close, fd)
			
			# read everything back, compare to data we zip
			fd = os.open(path, os.O_RDONLY)
			written_data = os.read(fd, os.path.getsize(path))
			os.close(fd)
			assert written_data == zlib.compress(data, 1)	# best speed
			
			os.remove(path)
		# END for each os
	
	
class TestUtils(TestBase):
	def test_basics(self):
		assert to_hex_sha(Blob.NULL_HEX_SHA) == Blob.NULL_HEX_SHA
		assert len(to_bin_sha(Blob.NULL_HEX_SHA)) == 20
		assert to_hex_sha(to_bin_sha(Blob.NULL_HEX_SHA)) == Blob.NULL_HEX_SHA
		

class TestDB(TestBase):
	"""Test the different db class implementations"""
	
	# data
	two_lines = "1234\nhello world"
	
	all_data = (two_lines, )
	
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
					
				istream = IStream(Blob.type, len(data), StringIO(data))
				
				# store returns same istream instance, with new sha set
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
					
					# DIRECT STREAM COPY
					# our data hase been written in object format to the StringIO
					# we pasesd as output stream. No physical database representation
					# was created.
					# Test direct stream copy of object streams, the result must be 
					# identical to what we fed in
					ostream.seek(0)
					istream.stream = ostream
					assert istream.sha is not None
					prev_sha = istream.sha
					
					db.set_ostream(ZippedStoreShaWriter())
					db.store(istream)
					assert istream.sha == prev_sha
					new_ostream = db.ostream()
					
					# note: only works as long our store write uses the same compression
					# level, which is zip
					assert ostream.getvalue() == new_ostream.getvalue()
			# END for each data set
		# END for each dry_run mode
				
	@with_bare_rw_repo
	def test_writing(self, rwrepo):
		ldb = LooseObjectDB(os.path.join(rwrepo.git_dir, 'objects'))
		
		# write data
		self._assert_object_writing(ldb)
	
