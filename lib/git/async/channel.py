"""Contains a queue based channel implementation"""
from Queue import (
	Empty, 
	Full
	)

from util import (
		AsyncQueue, 
		SyncQueue,
		ReadOnly
		)

from time import time
import sys

#{ Classes 
class Channel(object):
	"""A channel is similar to a file like object. It has a write end as well as one or
	more read ends. If Data is in the channel, it can be read, if not the read operation
	will block until data becomes available.
	If the channel is closed, any read operation will result in an exception
	
	This base class is not instantiated directly, but instead serves as constructor
	for Rwriter pairs.
	
	Create a new channel """
	__slots__ = 'queue'
	
	# The queue to use to store the actual data
	QueueCls = AsyncQueue
	
	def __init__(self):
		"""initialize this instance with a queue holding the channel contents""" 
		self.queue = self.QueueCls()


class SerialChannel(Channel):
	"""A slightly faster version of a Channel, which sacrificed thead-safety for performance"""
	QueueCls = SyncQueue


class Writer(object):
	"""The write end of a channel, a file-like interface for a channel"""
	__slots__ = ('write', 'channel')
	
	def __init__(self, channel):
		"""Initialize the writer to use the given channel"""
		self.channel = channel
		self.write = channel.queue.put
	
	#{ Interface
	def size(self):
		return self.channel.queue.qsize()
		
	def close(self):
		"""Close the channel. Multiple close calls on a closed channel are no 
		an error"""
		self.channel.queue.set_writable(False)
		
	def closed(self):
		""":return: True if the channel was closed"""
		return not self.channel.queue.writable()
	#} END interface 
	

class CallbackWriter(Writer):
	"""The write end of a channel which allows you to setup a callback to be 
	called after an item was written to the channel"""
	__slots__ = ('_pre_cb')
	
	def __init__(self, channel):
		Writer.__init__(self, channel)
		self._pre_cb = None
		self.write = self._write
	
	def set_pre_cb(self, fun = lambda item: item):
		"""Install a callback to be called before the given item is written.
		It returns a possibly altered item which will be written to the channel
		instead, making it useful for pre-write item conversions.
		Providing None uninstalls the current method.
		:return: the previously installed function or None
		:note: Must be thread-safe if the channel is used in multiple threads"""
		prev = self._pre_cb
		self._pre_cb = fun
		return prev
	
	def _write(self, item, block=True, timeout=None):
		if self._pre_cb:
			item = self._pre_cb(item)
		self.channel.queue.put(item, block, timeout)
	

class Reader(object):
	"""Allows reading from a channel"""
	__slots__ = 'channel'
	
	def __init__(self, channel):
		"""Initialize this instance from its parent write channel"""
		self.channel = channel
		
		
	#{ Interface
	
	def read(self, count=0, block=True, timeout=None):
		"""read a list of items read from the channel. The list, as a sequence
		of items, is similar to the string of characters returned when reading from 
		file like objects.
		:param count: given amount of items to read. If < 1, all items will be read
		:param block: if True, the call will block until an item is available
		:param timeout: if positive and block is True, it will block only for the 
			given amount of seconds, returning the items it received so far.
			The timeout is applied to each read item, not for the whole operation.
		:return: single item in a list if count is 1, or a list of count items. 
			If the channel was empty and count was 1, an empty list will be returned.
			If count was greater 1, a list with less than count items will be 
			returned.
			If count was < 1, a list with all items that could be read will be 
			returned."""
		# if the channel is closed for writing, we never block
		# NOTE: is handled by the queue
		# We don't check for a closed state here has it costs time - most of 
		# the time, it will not be closed, and will bail out automatically once
		# it gets closed
		
		
		# in non-blocking mode, its all not a problem
		out = list()
		queue = self.channel.queue
		if not block:
			# be as fast as possible in non-blocking mode, hence
			# its a bit 'unrolled'
			try:
				if count == 1:
					out.append(queue.get(False))
				elif count < 1:
					while True:
						out.append(queue.get(False))
					# END for each item
				else:
					for i in xrange(count):
						out.append(queue.get(False))
					# END for each item
				# END handle count
			except Empty:
				pass
			# END handle exceptions
		else:
			# to get everything into one loop, we set the count accordingly
			if count == 0:
				count = sys.maxint
			# END handle count
			
			i = 0
			while i < count:
				try:
					out.append(queue.get(block, timeout))
					i += 1
				except Empty:
					# here we are only if 
					# someone woke us up to inform us about the queue that changed
					# its writable state
					# The following branch checks for closed channels, and pulls
					# as many items as we need and as possible, before 
					# leaving the loop.
					if not queue.writable():
						try:
							while i < count:
								out.append(queue.get(False, None))
								i += 1
							# END count loop
						except Empty:
							break	# out of count loop 
						# END handle absolutely empty queue
					# END handle closed channel 
					
					# if we are here, we woke up and the channel is not closed
					# Either the queue became writable again, which currently shouldn't
					# be able to happen in the channel, or someone read with a timeout
					# that actually timed out.
					# As it timed out, which is the only reason we are here, 
					# we have to abort
					break
				# END ignore empty
				
			# END for each item
		# END handle blocking
		return out
		
	#} END interface 

class CallbackReader(Reader):
	"""A channel which sends a callback before items are read from the channel"""
	__slots__ = "_pre_cb"
	
	def __init__(self, channel):
		Reader.__init__(self, channel)
		self._pre_cb = None
	
	def set_pre_cb(self, fun = lambda count: None):
		"""Install a callback to call with the item count to be read before any 
		item is actually read from the channel. 
		Exceptions will be propagated.
		If a function is not provided, the call is effectively uninstalled.
		:return: the previously installed callback or None
		:note: The callback must be threadsafe if the channel is used by multiple threads."""
		prev = self._pre_cb
		self._pre_cb = fun
		return prev
	
	def read(self, count=0, block=True, timeout=None):
		if self._pre_cb:
			self._pre_cb(count)
		return Reader.read(self, count, block, timeout)


#} END classes

#{ Constructors
def mkchannel(ctype = Channel, wtype = Writer, rtype = Reader):
	"""Create a channel, with a reader and a writer
	:return: tuple(reader, writer)
	:param ctype: Channel to instantiate
	:param wctype: The type of the write channel to instantiate
	:param rctype: The type of the read channel to instantiate"""
	c = ctype()
	wc = wtype(c)
	rc = rtype(c)
	return wc, rc
#} END constructors
