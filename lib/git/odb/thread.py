# -*- coding: utf-8 -*-
"""Module with threading utilities"""
__docformat__ = "restructuredtext"
import threading
import inspect
import Queue

#{ Decorators

def do_terminate_threads(whitelist=list()):
	"""Simple function which terminates all of our threads
	:param whitelist: If whitelist is given, only the given threads will be terminated"""
	for t in threading.enumerate():
		if not isinstance(t, TerminatableThread):
			continue
		if whitelist and t not in whitelist:
			continue
		if isinstance(t, WorkerThread):
			t.inq.put(t.quit)
		# END worker special handling
		t.stop_and_join()
	# END for each thread

def terminate_threads( func ):
	"""Kills all worker threads the method has created by sending the quit signal.
	This takes over in case of an error in the main function"""
	def wrapper(*args, **kwargs):
		cur_threads = set(threading.enumerate())
		try:
			return func(*args, **kwargs)
		finally:
			do_terminate_threads(set(threading.enumerate()) - cur_threads)
		# END finally shutdown threads
	# END wrapper 
	wrapper.__name__ = func.__name__
	return wrapper

#} END decorators

#{ Classes
	
class TerminatableThread(threading.Thread):
	"""A simple thread able to terminate itself on behalf of the user.
	
	Terminate a thread as follows:
	
	t.stop_and_join()
	
	Derived classes call _should_terminate() to determine whether they should 
	abort gracefully
	"""
	__slots__ = '_terminate'
	
	def __init__(self):
		super(TerminatableThread, self).__init__()
		self._terminate = False
		
		
	#{ Subclass Interface
	def _should_terminate(self):
		""":return: True if this thread should terminate its operation immediately"""
		return self._terminate
		
	def _terminated(self):
		"""Called once the thread terminated. Its called in the main thread
		and may perform cleanup operations"""
		pass

	def start(self):
		"""Start the thread and return self"""
		super(TerminatableThread, self).start()
		return self
	
	#} END subclass interface
		
	#{ Interface 
		
	def stop_and_join(self):
		"""Ask the thread to stop its operation and wait for it to terminate
		:note: Depending on the implenetation, this might block a moment"""
		self._terminate = True
		self.join()
		self._terminated()
	#} END interface
	

class WorkerThread(TerminatableThread):
	"""
	This base allows to call functions on class instances natively and retrieve
	their results asynchronously using a queue.
	The thread runs forever unless it receives the terminate signal using 
	its task queue.
	
	Tasks could be anything, but should usually be class methods and arguments to
	allow the following:
	
	inq = Queue()
	outq = Queue()
	w = WorkerThread(inq, outq)
	w.start()
	inq.put((WorkerThread.<method>, args, kwargs))
	res = outq.get()
	
	finally we call quit to terminate asap.
	
	alternatively, you can make a call more intuitively - the output is the output queue
	allowing you to get the result right away or later
	w.call(arg, kwarg='value').get()
	
	inq.put(WorkerThread.quit)
	w.join()
	
	You may provide the following tuples as task:
	t[0] = class method, function or instance method
	t[1] = optional, tuple or list of arguments to pass to the routine
	t[2] = optional, dictionary of keyword arguments to pass to the routine
	"""
	__slots__ = ('inq', 'outq')
	
	class InvalidRoutineError(Exception):
		"""Class sent as return value in case of an error"""
		
	def __init__(self, inq = None, outq = None):
		super(WorkerThread, self).__init__()
		self.inq = inq or Queue.Queue()
		self.outq = outq or Queue.Queue()
	
	def call(self, function, *args, **kwargs):
		"""Method that makes the call to the worker using the input queue, 
		returning our output queue
		
		:param funciton: can be a standalone function unrelated to this class, 
			a class method of this class or any instance method.
			If it is a string, it will be considered a function residing on this instance
		:param args: arguments to pass to function
		:parma **kwargs: kwargs to pass to function"""
		self.inq.put((function, args, kwargs))
		return self.outq
	
	def wait_until_idle(self):
		"""wait until the input queue is empty, in the meanwhile, take all 
		results off the output queue."""
		while not self.inq.empty():
			try:
				self.outq.get(False)
			except Queue.Empty:
				continue
		# END while there are tasks on the queue
	
	def run(self):
		"""Process input tasks until we receive the quit signal"""
		while True:
			if self._should_terminate():
				break
			# END check for stop request
			routine = self.__class__.quit
			args = tuple()
			kwargs = dict()
			tasktuple = self.inq.get()
			
			if isinstance(tasktuple, (tuple, list)):
				if len(tasktuple) == 3:
					routine, args, kwargs = tasktuple
				elif len(tasktuple) == 2:
					routine, args = tasktuple
				elif len(tasktuple) == 1:
					routine = tasktuple[0]
				# END tasktuple length check
			elif inspect.isroutine(tasktuple):
				routine = tasktuple
			# END tasktuple handling
			
			try:
				rval = None
				if inspect.ismethod(routine):
					if routine.im_self is None:
						rval = routine(self, *args, **kwargs)
					else:
						rval = routine(*args, **kwargs)
				elif inspect.isroutine(routine):
					rval = routine(*args, **kwargs)
				elif isinstance(routine, basestring) and hasattr(self, routine):
					rval = getattr(self, routine)(*args, **kwargs)
				else:
					# ignore unknown items
					print "%s: task %s was not understood - terminating" % (self.getName(), str(tasktuple))
					self.outq.put(self.InvalidRoutineError(routine))
					break
				# END make routine call
				self.outq.put(rval)
			except StopIteration:
				break
			except Exception,e:
				print "%s: Task %s raised unhandled exception: %s" % (self.getName(), str(tasktuple), str(e))
				self.outq.put(e)
			# END routine exception handling
		# END endless loop
	
	def quit(self):
		raise StopIteration
	
	
#} END classes
