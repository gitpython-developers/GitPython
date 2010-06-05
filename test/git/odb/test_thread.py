# -*- coding: utf-8 -*-
""" Test thead classes and functions"""
from test.testlib import *
from git.odb.thread import *
from Queue import Queue

class TestWorker(WorkerThread):
	def __init__(self, *args, **kwargs):
		super(TestWorker, self).__init__(*args, **kwargs)
		self.reset()
		
	def fun(self, *args, **kwargs):
		self.called = True
		self.args = args 
		self.kwargs = kwargs
		return True
		
	def make_assertion(self):
		assert self.called
		assert self.args
		assert self.kwargs
		self.reset()
		
	def reset(self):
		self.called = False
		self.args = None
		self.kwargs = None
		

class TestCase( TestCase ):
	
	@terminate_threads
	def test_worker_thread(self):
		worker = TestWorker()
		assert isinstance(worker.start(), WorkerThread)
		
		# test different method types
		standalone_func = lambda *args, **kwargs: worker.fun(*args, **kwargs)
		for function in ("fun", TestWorker.fun, worker.fun, standalone_func):
			rval = worker.call(function, 1, this='that')
			assert isinstance(rval, Queue)
			assert rval.get() is True
			worker.make_assertion()
		# END for each function type
		
		worker.call('quit')
	
