"""Channel testing"""
from test.testlib import *
from git.async.channel import *

import time

class TestChannels(TestBase):
	
	def test_base(self):
		# creating channel yields a write and a read channal
		wc, rc = Channel()
		assert isinstance(wc, WChannel)
		assert isinstance(rc, RChannel)
		
		# everything else fails
		self.failUnlessRaises(ValueError, Channel, 1, "too many args")
		
		# TEST UNLIMITED SIZE CHANNEL - writing+reading is FIFO
		item = 1
		item2 = 2
		wc.write(item)
		wc.write(item2)
		assert rc.read() == item
		assert rc.read() == item2
		
		# next read blocks, then raises - it waits a second
		st = time.time()
		self.failUnlessRaises(IOError, rc.read, True, 1)
		assert time.time() - st >= 1.0
		
		# writing to a closed channel raises
		assert not wc.closed
		wc.close()
		assert wc.closed
		wc.close()	# fine
		assert wc.closed
		
		self.failUnlessRaises(IOError, wc.write, 1)
		
		# reading from a closed channel never blocks
		self.failUnlessRaises(IOError, rc.read)
		
		
		
		# TEST LIMITED SIZE CHANNEL
		# channel with max-items set
		wc, rc = Channel(1)
		wc.write(item)			# fine
		
		# blocks for a second, its full
		st = time.time()
		self.failUnlessRaises(IOError, wc.write, item, True, 1)
		assert time.time() - st >= 1.0
		
		# get one
		assert rc.read() == item
		
		# its empty,can put one again
		wc.write(item2)
		assert rc.read() == item2
		wc.close()
