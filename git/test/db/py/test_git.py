# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from lib import *
from git.exc import BadObject
from git.db.py import PureGitODB
from git.base import OStream, OInfo
from git.util import hex_to_bin, bin_to_hex
		
class TestGitDB(TestDBBase):
	
	def test_reading(self):
		gdb = PureGitODB(fixture_path('../../../.git/objects'))
		
		# we have packs and loose objects, alternates doesn't necessarily exist
		assert 1 < len(gdb.databases()) < 4
		
		# access should be possible
		git_sha = hex_to_bin("5690fd0d3304f378754b23b098bd7cb5f4aa1976")
		assert isinstance(gdb.info(git_sha), OInfo)
		assert isinstance(gdb.stream(git_sha), OStream)
		assert gdb.size() > 200
		sha_list = list(gdb.sha_iter())
		assert len(sha_list) == gdb.size()
		
		
		# This is actually a test for compound functionality, but it doesn't 
		# have a separate test module
		# test partial shas
		# this one as uneven and quite short
		assert gdb.partial_to_complete_sha_hex('155b6') == hex_to_bin("155b62a9af0aa7677078331e111d0f7aa6eb4afc")
		
		# mix even/uneven hexshas
		for i, binsha in enumerate(sha_list):
			assert gdb.partial_to_complete_sha_hex(bin_to_hex(binsha)[:8-(i%2)]) == binsha
		# END for each sha
		
		self.failUnlessRaises(BadObject, gdb.partial_to_complete_sha_hex, "0000")
		
	@with_rw_directory
	def test_writing(self, path):
		gdb = PureGitODB(path)
		
		# its possible to write objects
		self._assert_object_writing(gdb)
		self._assert_object_writing_async(gdb)
