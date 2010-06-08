"""Module with utilities related to async operations"""

from threading import (
	Lock,
	current_thread,
	_allocate_lock,
	_Condition, 
	_sleep,
	_time,
	)

from Queue import (
		Queue, 
		Empty,
		)

from collections import deque
import sys
import os

#{ Routines 

def cpu_count():
	""":return:number of CPUs in the system
	:note: inspired by multiprocessing"""
	num = 0
	try:
		if sys.platform == 'win32':
			num = int(os.environ['NUMBER_OF_PROCESSORS'])
		elif 'bsd' in sys.platform or sys.platform == 'darwin':
			num = int(os.popen('sysctl -n hw.ncpu').read())
		else:
			num = os.sysconf('SC_NPROCESSORS_ONLN')
	except (ValueError, KeyError, OSError, AttributeError):
		pass
	# END exception handling
	
	if num == 0:
		raise NotImplementedError('cannot determine number of cpus')
	
	return num
	
#} END routines



class DummyLock(object):
	"""An object providing a do-nothing lock interface for use in sync mode"""
	__slots__ = tuple()
	
	def acquire(self):
		pass
	
	def release(self):
		pass
	

class SyncQueue(deque):
	"""Adapter to allow using a deque like a queue, without locking"""
	def get(self, block=True, timeout=None):
		try:
			return self.popleft()
		except IndexError:
			raise Empty
		# END raise empty

	def empty(self):
		return len(self) == 0
		
	put = deque.append
	

class HSCondition(object):
	"""An attempt to make conditions less blocking, which gains performance 
	in return by sleeping less"""
	# __slots__ = ("acquire", "release", "_lock", '_waiters')
	__slots__ = ("_lock", '_waiters')
	delay = 0.00002		# reduces wait times, but increases overhead
	
	def __init__(self, lock=None):
		if lock is None:
			lock = Lock()
		self._lock = lock
		#self.acquire = lock.acquire
		#self.release = lock.release
		self._waiters = list()

	def release(self):
		self._lock.release()
		
	def acquire(self, block=None):
		if block is None:
			self._lock.acquire()
		else:
			self._lock.acquire(block)

	def wait(self, timeout=None):
		waiter = _allocate_lock()
		waiter.acquire()				# get it the first time, no blocking
		self._waiters.append(waiter)
		
		# in the momemnt we release our lock, someone else might actually resume
		self.release()
		try:	# restore state no matter what (e.g., KeyboardInterrupt)
			# now we block, as we hold the lock already
			if timeout is None:
				waiter.acquire()
			else:
				# Balancing act:  We can't afford a pure busy loop, because of the 
				# GIL, so we have to sleep
				# We try to sleep only tiny amounts of time though to be very responsive
				endtime = _time() + timeout
				delay = self.delay
				acquire = waiter.acquire
				while True:
					gotit = acquire(0)
					if gotit:
						break
					remaining = endtime - _time()
					if remaining <= 0:
						break
					# this makes 4 threads working as good as two, but of course
					# it causes more frequent micro-sleeping
					#delay = min(delay * 2, remaining, .05)
					_sleep(delay)
				# END endless loop
				if not gotit:
					try:
						self._waiters.remove(waiter)
					except ValueError:
						pass
				# END didn't ever get it
		finally:
			# reacquire the lock 
			self.acquire()
			
	def notify(self, n=1):
		if not self._waiters:
			return
		waiters = self._waiters
		if n == 1:
			waiters[0].release()
			try:
				waiters.pop(0)
			except IndexError:
				pass
		else:
			print "notify", waiters, n
			for waiter in waiters[:n]:
				waiter.release()
				try:
					waiters.remove(waiter)
				except ValueError:
					pass
		# END handle n = 1 case faster
	
	def notify_all(self):
		self.notify(len(self._waiters))
		

class ReadOnly(Exception):
	"""Thrown when trying to write to a read-only queue"""

class AsyncQueue(Queue):
	"""A queue using different condition objects to gain multithreading performance.
	Additionally it has a threadsafe writable flag, which will alert all readers
	that there is nothing more to get here."""
	__slots__ = ('mutex', 'not_empty', 'queue', '_writable')
	
	def __init__(self, maxsize=0):
		self.queue = deque()
		self.mutex = Lock()
		self.not_empty = HSCondition(self.mutex)
		self._writable = True
		
	def qsize(self):
		self.mutex.acquire()
		try:
			return len(self.queue)
		finally:
			self.mutex.release()

	def writable(self):
		self.mutex.acquire()
		try:
			return self._writable
		finally:
			self.mutex.release()

	def set_writable(self, state):
		"""Set the writable flag of this queue to True or False
		:return: The previous state"""
		self.mutex.acquire()
		try:
			old = self._writable
			self._writable = state
			return old
		finally:
			self.mutex.release()
			
			# if we won't receive anymore items, inform the getters
			if not state:
				self.not_empty.notify_all()
			# END tell everyone
		# END handle locking

	def empty(self):
		self.mutex.acquire()
		try:
			return not len(self.queue)
		finally:
			self.mutex.release()

	def put(self, item, block=True, timeout=None):
		self.mutex.acquire()
		if not self._writable:
			self.mutex.release()
			raise ReadOnly
		# END handle read-only
		self.queue.append(item)
		self.mutex.release()
		self.not_empty.notify()
		
	def get(self, block=True, timeout=None):
		self.not_empty.acquire()	# == self.mutex.acquire in that case
		q = self.queue
		try:
			if block:
				if timeout is None:
					while not len(q) and self._writable:
						self.not_empty.wait()
				else:
					endtime = _time() + timeout
					while not len(q) and self._writable:
						remaining = endtime - _time()
						if remaining <= 0.0:
							raise Empty
						self.not_empty.wait(remaining)
				# END handle timeout mode
			# END handle block
			
			# can throw if we woke up because we are not writable anymore
			print len(q), id(q), current_thread()
			try:
				return q.popleft()
			except IndexError:
				raise Empty
			# END handle unblocking reason
		finally:
			self.not_empty.release()


#} END utilities
