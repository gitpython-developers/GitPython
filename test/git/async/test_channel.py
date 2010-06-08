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
		
		# read all - it blocks as its still open for writing
		to = 0.2
		st = time.time()
		assert rc.read(timeout=to) == [item, item2]
		assert time.time() - st >= to
		
		# next read blocks. it waits a second
		st = time.time()
		assert len(rc.read(1, True, to)) == 0
		assert time.time() - st >= to
		
		# writing to a closed channel raises
		assert not wc.closed
		wc.close()
		assert wc.closed
		wc.close()	# fine
		assert wc.closed
		
		self.failUnlessRaises(IOError, wc.write, 1)
		
		# reading from a closed channel never blocks
		assert len(rc.read()) == 0
				
