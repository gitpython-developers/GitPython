# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.test.lib import rorepo_dir
from git.test.db.base import RepoBase

from git.util import bin_to_hex
from git.exc import BadObject

from git.db.complex import CmdCompatibilityGitDB
from git.db.cmd.base import *

from git.refs import TagReference, Reference, RemoteReference

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
			
	def test_fetch_info(self):
		self.failUnlessRaises(ValueError, CmdCmdFetchInfo._from_line, self.rorepo, "nonsense", '')
		self.failUnlessRaises(ValueError, CmdCmdFetchInfo._from_line, self.rorepo, "? [up to date]      0.1.7RC    -> origin/0.1.7RC", '')
		
	
	def test_fetch_info(self):
		# assure we can handle remote-tracking branches
		fetch_info_line_fmt = "c437ee5deb8d00cf02f03720693e4c802e99f390	not-for-merge	%s '0.3' of git://github.com/gitpython-developers/GitPython"
		remote_info_line_fmt = "* [new branch]      nomatter     -> %s"
		fi = CmdFetchInfo._from_line(self.rorepo,
							remote_info_line_fmt % "local/master", 
							fetch_info_line_fmt % 'remote-tracking branch')
		
		# we wouldn't be here if it wouldn't have worked
		
		# handles non-default refspecs: One can specify a different path in refs/remotes
		# or a special path just in refs/something for instance
		
		fi = CmdFetchInfo._from_line(self.rorepo,
							remote_info_line_fmt % "subdir/tagname", 
							fetch_info_line_fmt % 'tag')
		
		assert isinstance(fi.ref, TagReference)
		assert fi.ref.path.startswith('refs/tags')
		
		# it could be in a remote direcftory though
		fi = CmdFetchInfo._from_line(self.rorepo,
							remote_info_line_fmt % "remotename/tags/tagname", 
							fetch_info_line_fmt % 'tag')
		
		assert isinstance(fi.ref, TagReference)
		assert fi.ref.path.startswith('refs/remotes/')
		
		# it can also be anywhere !
		tag_path = "refs/something/remotename/tags/tagname"
		fi = CmdFetchInfo._from_line(self.rorepo,
							remote_info_line_fmt % tag_path, 
							fetch_info_line_fmt % 'tag')
		
		assert isinstance(fi.ref, TagReference)
		assert fi.ref.path == tag_path
		
		# branches default to refs/remotes
		fi = CmdFetchInfo._from_line(self.rorepo,
							remote_info_line_fmt % "remotename/branch", 
							fetch_info_line_fmt % 'branch')
		
		assert isinstance(fi.ref, RemoteReference)
		assert fi.ref.remote_name == 'remotename'
		
		# but you can force it anywhere, in which case we only have a references
		fi = CmdFetchInfo._from_line(self.rorepo,
							remote_info_line_fmt % "refs/something/branch", 
							fetch_info_line_fmt % 'branch')
		
		assert type(fi.ref) is Reference
		assert fi.ref.path == "refs/something/branch"
		
					
	
