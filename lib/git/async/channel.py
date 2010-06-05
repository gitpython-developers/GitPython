"""Contains a queue based channel implementation"""
from Queue import (
	Queue, 
	Empty, 
	Full
	)

#{ Classes 
class Channel(object):
	"""A channel is similar to a system pipe. It has a write end as well as one or
	more read ends. If Data is in the channel, it can be read, if not the read operation
	will block until data becomes available.
	If the channel is closed, any read operation will result in an exception
	
	This base class is not instantiated directly, but instead serves as constructor
	for RWChannel pairs.
	
	Create a new channel """
	__slots__ = tuple()
	
	def __new__(cls, *args):
		if cls is Channel:
			max_items = 0
			if len(args) == 1:
				max_items = args[0]
			if len(args) > 1:
				raise ValueError("Specify not more than the number of items the channel should take")
			wc = WChannel(max_items)
			rc = RChannel(wc)
			return wc, rc
		# END constructor mode
		return object.__new__(cls)


class WChannel(Channel):
	"""The write end of a channel"""
	__slots__ = ('_closed', '_queue')
	
	def __init__(self, max_items=0):
		"""initialize this instance, able to hold max_items at once
		Write calls will block if the channel is full, until someone reads from it"""
		self._closed = False
		self._queue = Queue(max_items)
		
	
	#{ Interface 
	def write(self, item, block=True, timeout=None):
		"""Send an item into the channel, it can be read from the read end of the 
		channel accordingly
		:param item: Item to send
		:param block: If True, the call will block until there is free space in the 
			channel
		:param timeout: timeout in seconds for blocking calls.
		:raise IOError: when writing into closed file or when writing into a non-blocking
			full channel
		:note: may block if the channel has a limited capacity"""
		if self._closed:
			raise IOError("Cannot write to a closed channel")
			
		try:
			self._queue.put(item, block, timeout)
		except Full:
			raise IOError("Capacity of the channel was exeeded")
		# END exception handling
		
	def close(self):
		"""Close the channel. Multiple close calls on a closed channel are no 
		an error"""
		self._closed = True
		
	@property
	def closed(self):
		""":return: True if the channel was closed"""
		return self._closed
	#} END interface 
	

class RChannel(Channel):
	"""The read-end of a corresponding write channel"""
	__slots__ = '_wc'
	
	def __init__(self, wchannel):
		"""Initialize this instance from its parent write channel"""
		self._wc = wchannel
		
		
	#{ Interface
	
	def read(self, block=True, timeout=None):
		""":return: an item read from the channel
		:param block: if True, the call will block until an item is available
		:param timeout: if positive and block is True, it will block only for the 
			given amount of seconds.
		:raise IOError: When reading from an empty channel ( if non-blocking, or 
			if the channel is still empty after the timeout"""
		# if the channel is closed for writing, we never block
		if self._wc.closed:
			block = False
			
		try:
			return self._wc._queue.get(block, timeout)
		except Empty:
			raise IOError("Error reading from an empty channel")
		# END handle reading
		
	#} END interface 
	
#} END classes
