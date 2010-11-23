from git.test.lib import *
from git.objects import IndexObject, Actor
from git.refs import *

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
		pass
		# raise on invalid revlog
		# TODO: Try multiple corrupted ones !
	
	
		# test serialize and deserialize - results must match exactly
