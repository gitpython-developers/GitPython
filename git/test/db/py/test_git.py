# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.test.lib import rorepo_dir
from git.test.db.lib import TestDBBase, with_rw_directory
from git.exc import BadObject
from git.db.py.complex import PureGitODB
from git.base import OStream, OInfo
from git.util import hex_to_bin, bin_to_hex

import os

class TestGitDB(TestDBBase):
	needs_ro_repo = False
	
	def test_reading(self):
		gdb = PureGitODB(os.path.join(rorepo_dir(), 'objects'))
		
		# we have packs and loose objects, alternates doesn't necessarily exist
		assert 1 < len(gdb.databases()) < 4
		
		# access should be possible
		git_sha = hex_to_bin("5aebcd5cb3340fb31776941d7e4d518a712a8655")
		assert isinstance(gdb.info(git_sha), OInfo)
		assert isinstance(gdb.stream(git_sha), OStream)
		assert gdb.size() > 200
		sha_list = list(gdb.sha_iter())
		assert len(sha_list) == gdb.size()
		
		
		# This is actually a test for compound functionality, but it doesn't 
		# have a separate test module
		# test partial shas
		# this one as uneven and quite short
		assert gdb.partial_to_complete_sha_hex('5aebcd') == hex_to_bin("5aebcd5cb3340fb31776941d7e4d518a712a8655")
		
		# mix even/uneven hexshas
		for i, binsha in enumerate(sha_list[:50]):
			assert gdb.partial_to_complete_sha_hex(bin_to_hex(binsha)[:8-(i%2)]) == binsha
		# END for each sha
		
		self.failUnlessRaises(BadObject, gdb.partial_to_complete_sha_hex, "0000")
		
	@with_rw_directory
	def test_writing(self, path):
		gdb = PureGitODB(path)
		
		# its possible to write objects
		self._assert_object_writing(gdb)
		self._assert_object_writing_async(gdb)
