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
	for RWChannel pairs.
	
	Create a new channel """
	__slots__ = tuple()


class WChannel(Channel):
	"""The write end of a channel - it is thread-safe"""
	__slots__ = ('_queue')
	
	# The queue to use to store the actual data
	QueueCls = AsyncQueue
	
	def __init__(self):
		"""initialize this instance, able to hold max_items at once
		Write calls will block if the channel is full, until someone reads from it"""
		self._queue = self.QueueCls()
	
	#{ Interface 
	def write(self, item, block=True, timeout=None):
		"""Send an item into the channel, it can be read from the read end of the 
		channel accordingly
		:param item: Item to send
		:param block: If True, the call will block until there is free space in the 
			channel
		:param timeout: timeout in seconds for blocking calls.
		:raise ReadOnly: when writing into closed channel"""
		# let the queue handle the 'closed' attribute, we write much more often 
		# to an open channel than to a closed one, saving a few cycles
		self._queue.put(item, block, timeout)
		
	def size(self):
		""":return: approximate number of items that could be read from the read-ends
			of this channel"""
		return self._queue.qsize()
		
	def close(self):
		"""Close the channel. Multiple close calls on a closed channel are no 
		an error"""
		self._queue.set_writable(False)
		
	def closed(self):
		""":return: True if the channel was closed"""
		return not self._queue.writable()
	#} END interface 
	

class CallbackWChannel(WChannel):
	"""The write end of a channel which allows you to setup a callback to be 
	called after an item was written to the channel"""
	__slots__ = ('_pre_cb')
	
	def __init__(self):
		WChannel.__init__(self)
		self._pre_cb = None
	
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
	
	def write(self, item, block=True, timeout=None):
		if self._pre_cb:
			item = self._pre_cb(item)
		WChannel.write(self, item, block, timeout)
	
	
class SerialWChannel(WChannel):
	"""A slightly faster version of a WChannel, which sacrificed thead-safety for
	performance"""
	QueueCls = SyncQueue


class RChannel(Channel):
	"""The read-end of a corresponding write channel"""
	__slots__ = '_wc'
	
	def __init__(self, wchannel):
		"""Initialize this instance from its parent write channel"""
		self._wc = wchannel
		
		
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
		queue = self._wc._queue
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

class CallbackRChannel(RChannel):
	"""A channel which sends a callback before items are read from the channel"""
	__slots__ = "_pre_cb"
	
	def __init__(self, wc):
		RChannel.__init__(self, wc)
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
		return RChannel.read(self, count, block, timeout)


#} END classes

#{ Constructors
def mkchannel(wctype = WChannel, rctype = RChannel):
	"""Create a channel, which consists of one write end and one read end
	:return: tuple(write_channel, read_channel)
	:param wctype: The type of the write channel to instantiate
	:param rctype: The type of the read channel to instantiate"""
	wc = wctype()
	rc = rctype(wc)
	return wc, rc
#} END constructors
