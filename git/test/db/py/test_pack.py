# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
from git.test.db.lib import TestDBBase, with_packs_rw

from git.db.py.pack import PurePackedODB
from git.test.lib import fixture_path

from git.exc import BadObject, AmbiguousObjectName

import os
import random

class TestPackDB(TestDBBase):
	
	needs_ro_repo = False 
	
	@with_packs_rw
	def test_writing(self, path):
		pdb = PurePackedODB(path)
		
		# on demand, we init our pack cache
		num_packs = len(pdb.entities())
		assert num_packs
		assert pdb._st_mtime != 0
		
		# test pack directory changed: 
		# packs removed - rename a file, should affect the glob
		pack_path = pdb.entities()[0].pack().path()
		new_pack_path = pack_path + "renamed"
		os.rename(pack_path, new_pack_path)
		
		pdb.update_cache(force=True)
		assert len(pdb.entities()) == num_packs - 1
		
		# packs added
		os.rename(new_pack_path, pack_path)
		pdb.update_cache(force=True)
		assert len(pdb.entities()) == num_packs
	
		# bang on the cache
		# access the Entities directly, as there is no iteration interface
		# yet ( or required for now )
		sha_list = list(pdb.sha_iter())
		assert len(sha_list) == pdb.size()
		
		# hit all packs in random order
		random.shuffle(sha_list)
		
		for sha in sha_list:
			info = pdb.info(sha)
			stream = pdb.stream(sha)
		# END for each sha to query
		
		
		# test short finding - be a bit more brutal here
		max_bytes = 19
		min_bytes = 2
		num_ambiguous = 0
		for i, sha in enumerate(sha_list):
			short_sha = sha[:max((i % max_bytes), min_bytes)]
			try:
				assert pdb.partial_to_complete_sha(short_sha, len(short_sha)*2) == sha
			except AmbiguousObjectName:
				num_ambiguous += 1
				pass # valid, we can have short objects
			# END exception handling
		# END for each sha to find
		
		# we should have at least one ambiguous, considering the small sizes
		# but in our pack, there is no ambigious ... 
		# assert num_ambiguous
		
		# non-existing
		self.failUnlessRaises(BadObject, pdb.partial_to_complete_sha, "\0\0", 4)
