# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.test.lib import rorepo_dir
from git.test.db.base import RepoBase

from git.util import bin_to_hex
from git.exc import BadObject

from git.db.complex import CmdCompatibilityGitDB

class TestBase(RepoBase):
	RepoCls = CmdCompatibilityGitDB

	def test_basics(self):
		gdb = self.rorepo
		
		# partial to complete - works with everything
		hexsha = bin_to_hex(gdb.partial_to_complete_sha_hex("0.1.6"))
		assert len(hexsha) == 40
		
		assert bin_to_hex(gdb.partial_to_complete_sha_hex(hexsha[:20])) == hexsha
		
		# fails with BadObject
		for invalid_rev in ("0000", "bad/ref", "super bad"):
			self.failUnlessRaises(BadObject, gdb.partial_to_complete_sha_hex, invalid_rev)
