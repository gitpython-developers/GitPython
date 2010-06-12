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
import threading
import sys

__all__ = ('Channel', 'SerialChannel', 'Writer', 'ChannelWriter', 'CallbackChannelWriter',
			'Reader', 'ChannelReader', 'CallbackChannelReader', 'mkchannel', 'ReadOnly', 
			'IteratorReader')

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
	"""A writer is an object providing write access to a possibly blocking reading device"""
	__slots__ = tuple()
	
	#{ Interface
	
	def __init__(self, device):
		"""Initialize the instance with the device to write to"""
	
	def write(self, item, block=True, timeout=None):
		"""Write the given item into the device
		:param block: True if the device may block until space for the item is available
		:param timeout: The time in seconds to wait for the device to become ready 
		in blocking mode"""
		raise NotImplementedError()
		
	def size(self):
		""":return: number of items already in the device, they could be read with a reader"""
		raise NotImplementedError()
		
	def close(self):
		"""Close the channel. Multiple close calls on a closed channel are no 
		an error"""
		raise NotImplementedError()
		
	def closed(self):
		""":return: True if the channel was closed"""
		raise NotImplementedError()
		
	#} END interface
	

class ChannelWriter(Writer):
	"""The write end of a channel, a file-like interface for a channel"""
	__slots__ = ('channel', '_put')
	
	def __init__(self, channel):
		"""Initialize the writer to use the given channel"""
		self.channel = channel
		self._put = self.channel.queue.put
	
	#{ Interface
	def write(self, item, block=False, timeout=None):
		return self._put(item, block, timeout)
		
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
	

class CallbackChannelWriter(ChannelWriter):
	"""The write end of a channel which allows you to setup a callback to be 
	called after an item was written to the channel"""
	__slots__ = ('_pre_cb')
	
	def __init__(self, channel):
		super(CallbackChannelWriter, self).__init__(channel)
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
		super(CallbackChannelWriter, self).write(item, block, timeout)
	

class Reader(object):
	"""Allows reading from a device"""
	__slots__ = tuple()
	
	#{ Interface
	def __init__(self, device):
		"""Initialize the instance with the device to read from"""
		
	def read(self, count=0, block=True, timeout=None):
		"""read a list of items read from the device. The list, as a sequence
		of items, is similar to the string of characters returned when reading from 
		file like objects.
		:param count: given amount of items to read. If < 1, all items will be read
		:param block: if True, the call will block until an item is available
		:param timeout: if positive and block is True, it will block only for the 
			given amount of seconds, returning the items it received so far.
			The timeout is applied to each read item, not for the whole operation.
		:return: single item in a list if count is 1, or a list of count items. 
			If the device was empty and count was 1, an empty list will be returned.
			If count was greater 1, a list with less than count items will be 
			returned.
			If count was < 1, a list with all items that could be read will be 
			returned."""
		raise NotImplementedError()
		

class ChannelReader(Reader):
	"""Allows reading from a channel. The reader is thread-safe if the channel is as well"""
	__slots__ = 'channel'
	
	def __init__(self, channel):
		"""Initialize this instance from its parent write channel"""
		self.channel = channel
		
	#{ Interface
	
	def read(self, count=0, block=True, timeout=None):
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

class CallbackChannelReader(ChannelReader):
	"""A channel which sends a callback before items are read from the channel"""
	__slots__ = "_pre_cb"
	
	def __init__(self, channel):
		super(CallbackChannelReader, self).__init__(channel)
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
		return super(CallbackChannelReader, self).read(count, block, timeout)


class IteratorReader(Reader):
	"""A Reader allowing to read items from an iterator, instead of a channel.
	Reads will never block. Its thread-safe"""
	__slots__ = ("_empty", '_iter', '_lock')
	
	# the type of the lock to use when reading from the iterator
	lock_type = threading.Lock
	
	def __init__(self, iterator):
		self._empty = False
		if not hasattr(iterator, 'next'):
			raise ValueError("Iterator %r needs a next() function" % iterator)
		self._iter = iterator
		self._lock = self.lock_type()
		
	def read(self, count=0, block=True, timeout=None):
		"""Non-Blocking implementation of read"""
		# not threadsafe, but worst thing that could happen is that 
		# we try to get items one more time
		if self._empty:
			return list()
		# END early abort
		
		self._lock.acquire()
		try:
			if count == 0:
				self._empty = True
				return list(self._iter)
			else:
				out = list()
				it = self._iter
				for i in xrange(count):
					try:
						out.append(it.next())
					except StopIteration:
						self._empty = True
						break
					# END handle empty iterator
				# END for each item to take
				return out
			# END handle count
		finally:
			self._lock.release()
		# END handle locking
		

#} END classes

#{ Constructors
def mkchannel(ctype = Channel, wtype = ChannelWriter, rtype = ChannelReader):
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
