# -*- coding: utf-8 -*-
""" Test thead classes and functions"""
from test.testlib import *
from git.async.thread import *
from Queue import Queue
import time

class TestWorker(WorkerThread):
	def __init__(self, *args, **kwargs):
		super(TestWorker, self).__init__(*args, **kwargs)
		self.reset()
		
	def fun(self, arg):
		self.called = True
		self.arg = arg 
		return True
		
	def make_assertion(self):
		assert self.called
		assert self.arg
		self.reset()
		
	def reset(self):
		self.called = False
		self.arg = None
		

class TestThreads( TestCase ):
	
	@terminate_threads
	def test_worker_thread(self):
		worker = TestWorker()
		assert isinstance(worker.start(), WorkerThread)
		
		# test different method types
		standalone_func = lambda *args, **kwargs: worker.fun(*args, **kwargs)
		for function in (TestWorker.fun, worker.fun, standalone_func):
			worker.inq.put((function, 1))
			time.sleep(0.01)
			worker.make_assertion()
		# END for each function type
		
		worker.stop_and_join()
	
