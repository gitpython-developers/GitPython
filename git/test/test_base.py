# test_base.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
from lib import (
				TestBase,
				with_rw_repo,
				DummyStream,
				DeriveTest,
				with_rw_and_rw_remote_repo
				)

import git.objects.base as base
from git.objects import (
							Blob, 
							Tree,
							Commit,
							TagObject
						)
import git.refs as refs


from itertools import chain
from git.objects.util import get_object_type_by_name
from git.util import hex_to_bin
import tempfile

##################

from git.util import (
	NULL_BIN_SHA
	)

from git.typ import str_blob_type
from git.base import (
						OInfo, 
						OPackInfo, 
						ODeltaPackInfo, 
						OStream, 
						OPackStream,
						ODeltaPackStream,
						IStream,
					)

import os

class TestBase(TestBase):
	
	type_tuples = (	 ("blob", "8741fc1d09d61f02ffd8cded15ff603eff1ec070", "blob.py"), 
					 ("tree", "3a6a5e3eeed3723c09f1ef0399f81ed6b8d82e79", "directory"),
					 ("commit", "4251bd59fb8e11e40c40548cba38180a9536118c", None),
					 ("tag", "e56a60e8e9cd333cfba0140a77cd12b0d9398f10", None) ) 
	
	def test_base_object(self): 
		# test interface of base object classes
		types = (Blob, Tree, Commit, TagObject)
		assert len(types) == len(self.type_tuples)
		
		s = set()
		num_objs = 0
		num_index_objs = 0
		for obj_type, (typename, hexsha, path) in zip(types, self.type_tuples):
			binsha = hex_to_bin(hexsha)
			item = None
			if path is None:
				item = obj_type(self.rorepo,binsha)
			else:
				item = obj_type(self.rorepo,binsha, 0, path)
			# END handle index objects
			num_objs += 1
			assert item.hexsha == hexsha
			assert item.type == typename
			assert item.size
			assert item == item
			assert not item != item
			assert str(item) == item.hexsha
			assert repr(item)
			s.add(item)
			
			if isinstance(item, base.IndexObject):
				num_index_objs += 1
				if hasattr(item,'path'):						# never runs here
					assert not item.path.startswith("/")		# must be relative
					assert isinstance(item.mode, int)
			# END index object check
			
			# read from stream
			data_stream = item.data_stream
			data = data_stream.read()
			assert data
			
			tmpfile = os.tmpfile()
			assert item == item.stream_data(tmpfile)
			tmpfile.seek(0)
			assert tmpfile.read() == data
			# END stream to file directly
		# END for each object type to create
		
		# each has a unique sha
		assert len(s) == num_objs
		assert len(s|s) == num_objs
		assert num_index_objs == 2
		
	def test_get_object_type_by_name(self):
		for tname in base.Object.TYPES:
			assert base.Object in get_object_type_by_name(tname).mro()
		# END for each known type 
		
		self.failUnlessRaises(ValueError, get_object_type_by_name, "doesntexist")

	def test_object_resolution(self):
		# objects must be resolved to shas so they compare equal
		assert self.rorepo.head.reference.object == self.rorepo.active_branch.object
		
	@with_rw_repo('HEAD', bare=True)
	def test_with_bare_rw_repo(self, bare_rw_repo):
		assert bare_rw_repo.config_reader("repository").getboolean("core", "bare")
		assert os.path.isfile(os.path.join(bare_rw_repo.git_dir,'HEAD'))
		
	@with_rw_repo('0.1.6')
	def test_with_rw_repo(self, rw_repo):
		assert not rw_repo.config_reader("repository").getboolean("core", "bare")
		assert os.path.isdir(os.path.join(rw_repo.working_tree_dir,'lib'))
		
	@with_rw_and_rw_remote_repo('0.1.6')
	def test_with_rw_remote_and_rw_repo(self, rw_repo, rw_remote_repo):
		assert not rw_repo.config_reader("repository").getboolean("core", "bare")
		assert rw_remote_repo.config_reader("repository").getboolean("core", "bare")
		assert os.path.isdir(os.path.join(rw_repo.working_tree_dir,'lib'))
		
		

class TestBaseTypes(TestBase):
	
	def test_streams(self):
		# test info
		sha = NULL_BIN_SHA
		s = 20
		blob_id = 3
		
		info = OInfo(sha, str_blob_type, s)
		assert info.binsha == sha
		assert info.type == str_blob_type
		assert info.type_id == blob_id
		assert info.size == s
		
		# test pack info
		# provides type_id
		pinfo = OPackInfo(0, blob_id, s)
		assert pinfo.type == str_blob_type
		assert pinfo.type_id == blob_id
		assert pinfo.pack_offset == 0
		
		dpinfo = ODeltaPackInfo(0, blob_id, s, sha)
		assert dpinfo.type == str_blob_type
		assert dpinfo.type_id == blob_id
		assert dpinfo.delta_info == sha
		assert dpinfo.pack_offset == 0
		
		
		# test ostream
		stream = DummyStream()
		ostream = OStream(*(info + (stream, )))
		assert ostream.stream is stream
		ostream.read(15)
		stream._assert()
		assert stream.bytes == 15
		ostream.read(20)
		assert stream.bytes == 20
		
		# test packstream
		postream = OPackStream(*(pinfo + (stream, )))
		assert postream.stream is stream
		postream.read(10)
		stream._assert()
		assert stream.bytes == 10
		
		# test deltapackstream
		dpostream = ODeltaPackStream(*(dpinfo + (stream, )))
		dpostream.stream is stream
		dpostream.read(5)
		stream._assert()
		assert stream.bytes == 5
		
		# derive with own args
		DeriveTest(sha, str_blob_type, s, stream, 'mine',myarg = 3)._assert()
		
		# test istream
		istream = IStream(str_blob_type, s, stream)
		assert istream.binsha == None
		istream.binsha = sha
		assert istream.binsha == sha
		
		assert len(istream.binsha) == 20
		assert len(istream.hexsha) == 40
		
		assert istream.size == s
		istream.size = s * 2
		istream.size == s * 2
		assert istream.type == str_blob_type
		istream.type = "something"
		assert istream.type == "something"
		assert istream.stream is stream
		istream.stream = None
		assert istream.stream is None
		
		assert istream.error is None
		istream.error = Exception()
		assert isinstance(istream.error, Exception)


