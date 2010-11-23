from git.test.lib import *
from git.objects import IndexObject
from git.refs import *
from git.util import Actor

import tempfile
import shutil
import os

class TestRefLog(TestBase):

	def test_reflogentry(self):
		nullhexsha = IndexObject.NULL_HEX_SHA
		hexsha = 'F' * 40
		actor = Actor('name', 'email')
		msg = "message"
		
		self.failUnlessRaises(ValueError, RefLogEntry.new, nullhexsha, hexsha, 'noactor', 0, 0, "")
		e = RefLogEntry.new(nullhexsha, hexsha, actor, 0, 1, msg)
		
		assert e.oldhexsha == nullhexsha
		assert e.newhexsha == hexsha
		assert e.actor == actor
		assert e.time[0] == 0
		assert e.time[1] == 1
		assert e.message == msg
		
		# check representation (roughly)
		assert repr(e).startswith(nullhexsha)
	
	def test_base(self):
		rlp_head = fixture_path('reflog_HEAD')
		rlp_master = fixture_path('reflog_master')
		tdir = tempfile.mktemp(suffix="test_reflogs")
		os.mkdir(tdir)
		
		# verify we have a ref - with the creation of a new ref, the reflog
		# will be created as well
		rlp_master_ro = RefLog.path(self.rorepo.heads.master) 
		assert os.path.isfile(rlp_master_ro)
		
		# simple read
		reflog = RefLog.from_file(rlp_master_ro)
		assert reflog._path is not None
		assert isinstance(reflog, RefLog)
		assert len(reflog)
		
		# iter_entries works with path and with stream
		assert len(list(RefLog.iter_entries(open(rlp_master))))
		assert len(list(RefLog.iter_entries(rlp_master)))
		
		# raise on invalid revlog
		# TODO: Try multiple corrupted ones !
		pp = 'reflog_invalid_'
		for suffix in ('oldsha', 'newsha', 'email', 'date', 'sep'):
			self.failUnlessRaises(ValueError, RefLog.from_file, fixture_path(pp+suffix))
		#END for each invalid file
		
	
		# test serialize and deserialize - results must match exactly
		binsha = chr(255)*20
		msg = "my reflog message"
		for rlp in (rlp_head, rlp_master):
			reflog = RefLog.from_file(rlp)
			tfile = os.path.join(tdir, os.path.basename(rlp))
			reflog.to_file(tfile)
			
			# parsed result must match ...
			treflog = RefLog.from_file(tfile)
			assert treflog == reflog
			
			# ... as well as each bytes of the written stream
			assert open(tfile).read() == open(rlp).read()
			
			# append an entry - it gets written automatically
			entry = treflog.append_entry(IndexObject.NULL_BIN_SHA, binsha, msg)
			assert entry.oldhexsha == IndexObject.NULL_HEX_SHA
			assert entry.newhexsha == 'f'*40
			assert entry.message == msg
			assert treflog == RefLog.from_file(tfile)
			
			# but not this time
			treflog.append_entry(binsha, binsha, msg, write=False)
			assert treflog != RefLog.from_file(tfile)
			
		# END for each reflog 
		
		
		# finally remove our temporary data
		shutil.rmtree(tdir)
