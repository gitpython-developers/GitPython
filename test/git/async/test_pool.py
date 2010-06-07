"""Channel testing"""
from test.testlib import *
from git.async.pool import *
from git.async.task import *
from git.async.util import cpu_count
import threading
import time

class TestThreadTaskNode(InputIteratorThreadTask):
	def __init__(self, *args, **kwargs):
		super(TestThreadTaskNode, self).__init__(*args, **kwargs)
		self.reset(self._iterator)
		self.should_fail = False
	
	def do_fun(self, item):
		self.item_count += 1
		if self.should_fail:
			raise AssertionError("I am failing just for the fun of it")
		return item
	
	def reset(self, iterator):
		self.process_count = 0
		self.item_count = 0
		self._iterator = iterator
		
	def process(self, count=1):
		super(TestThreadTaskNode, self).process(count)
		self.process_count += 1
		
	def _assert(self, pc, fc):
		"""Assert for num process counts (pc) and num function counts (fc)
		:return: self"""
		assert self.process_count == pc
		assert self.item_count == fc
		assert not self.error()
		return self
		

class TestThreadPool(TestBase):
	
	max_threads = cpu_count()
	
	def _assert_single_task(self, p, async=False):
		"""Performs testing in a synchronized environment"""
		null_tasks = p.num_tasks()		# in case we had some before
		
		# add a simple task
		# it iterates n items
		ni = 1000
		assert ni % 2 == 0, "ni needs to be dividable by 2"
		assert ni % 4 == 0, "ni needs to be dividable by 4"
		
		def make_iter():
			return iter(range(ni))
		# END utility
		
		task = TestThreadTaskNode(make_iter(), 'iterator', None)
		task.fun = task.do_fun
		
		assert p.num_tasks() == null_tasks
		rc = p.add_task(task)
		assert p.num_tasks() == 1 + null_tasks
		assert isinstance(rc, RPoolChannel)
		assert task._out_wc is not None
		
		# pull the result completely - we should get one task, which calls its 
		# function once. In sync mode, the order matches
		items = rc.read()
		assert len(items) == ni
		task._assert(1, ni).reset(make_iter())
		assert items[0] == 0 and items[-1] == ni-1
		
		# as the task is done, it should have been removed - we have read everything
		assert task.is_done()
		assert p.num_tasks() == null_tasks
		
		# pull individual items
		rc = p.add_task(task)
		assert p.num_tasks() == 1 + null_tasks
		st = time.time()
		for i in range(ni):
			items = rc.read(1)
			assert len(items) == 1
			
			# can't assert order in async mode
			if not async:
				assert i == items[0]
		# END for each item
		elapsed = time.time() - st
		print >> sys.stderr, "Threadpool: processed %i individual items, with %i threads, one at a time, in %f s ( %f items / s )" % (ni, p.size(), elapsed, ni / elapsed)
		
		# it couldn't yet notice that the input is depleted as we pulled exaclty 
		# ni items - the next one would remove it. Instead, we delete our channel 
		# which triggers orphan handling
		assert p.num_tasks() == 1 + null_tasks
		del(rc)
		assert p.num_tasks() == null_tasks
		
		task.reset(make_iter())
		
		# test min count
		# if we query 1 item, it will prepare ni / 2
		task.min_count = ni / 2
		rc = p.add_task(task)
		assert len(rc.read(1)) == 1			# processes ni / 2
		assert len(rc.read(1)) == 1			# processes nothing
		# rest - it has ni/2 - 2 on the queue, and pulls ni-2
		# It wants too much, so the task realizes its done. The task
		# doesn't care about the items in its output channel 
		assert len(rc.read(ni-2)) == ni - 2
		assert p.num_tasks() == null_tasks
		task._assert(2, ni)						# two chunks, 20 calls ( all items )
		
		# its already done, gives us no more
		assert len(rc.read()) == 0
		
		# test chunking
		# we always want 4 chunks, these could go to individual nodes
		task.reset(make_iter())
		task.max_chunksize = ni / 4			# 4 chunks
		rc = p.add_task(task)
		# must read a specific item count
		# count is still at ni / 2 - here we want more than that
		# 2 steps with n / 4 items, + 1 step with n/4 items to get + 2
		assert len(rc.read(ni / 2 + 2)) == ni / 2 + 2
		# have n / 4 - 2 items on queue, want n / 4 in first chunk, cause 1 processing
		# ( 4 in total ). Still want n / 4 - 2 in second chunk, causing another processing
		assert len(rc.read(ni / 2 - 2)) == ni / 2 - 2
		
		task._assert( 5, ni)
		assert p.num_tasks() == null_tasks	# depleted
		
		# but this only hits if we want too many items, if we want less, it could 
		# still do too much - hence we set the min_count to the same number to enforce
		# at least ni / 4 items to be preocessed, no matter what we request
		task.reset(make_iter())
		task.min_count = None
		rc = p.add_task(task)
		st = time.time()
		for i in range(ni):
			if async:
				assert len(rc.read(1)) == 1
			else:
				assert rc.read(1)[0] == i
			# END handle async mode
		# END pull individual items
		# too many processing counts ;)
		elapsed = time.time() - st
		print >> sys.stderr, "Threadpool: processed %i individual items in chunks of %i, with %i threads, one at a time, in %f s ( %f items / s )" % (ni, ni/4, p.size(), elapsed, ni / elapsed)
		
		task._assert(ni, ni)
		assert p.num_tasks() == 1 + null_tasks
		assert p.del_task(task) is p		# del manually this time
		assert p.num_tasks() == null_tasks
		
		# now with we set the minimum count to reduce the number of processing counts
		task.reset(make_iter())
		task.min_count = ni / 4
		rc = p.add_task(task)
		for i in range(ni):
			assert rc.read(1)[0] == i
		# END for each item
		task._assert(ni / task.min_count, ni)
		del(rc)
		assert p.num_tasks() == null_tasks
		
		# test failure
		# on failure, the processing stops and the task is finished, keeping 
		# his error for later
		task.reset(make_iter())
		task.should_fail = True
		rc = p.add_task(task)
		assert len(rc.read()) == 0		# failure on first item
		assert isinstance(task.error(), AssertionError)
		assert p.num_tasks() == null_tasks
		
	def _assert_async_dependent_tasks(self, p):
		# includes failure in center task, 'recursive' orphan cleanup
		# This will also verify that the channel-close mechanism works
		# t1 -> t2 -> t3
		# t1 -> x -> t3
		pass
	
	def test_base(self):
		p = ThreadPool()
		
		# default pools have no workers
		assert p.size() == 0
		
		# increase and decrease the size
		for i in range(self.max_threads):
			p.set_size(i)
			assert p.size() == i
		for i in range(self.max_threads, -1, -1):
			p.set_size(i)
			assert p.size() == i
			
		# SINGLE TASK SERIAL SYNC MODE
		##############################
		# put a few unrelated tasks that we forget about
		urc1 = p.add_task(TestThreadTaskNode(iter(list()), "nothing", None))
		urc2 = p.add_task(TestThreadTaskNode(iter(list()), "nothing", None))
		assert p.num_tasks() == 2
		
		## SINGLE TASK #################
		self._assert_single_task(p, False)
		assert p.num_tasks() == 2
		del(urc1)
		del(urc2)
		assert p.num_tasks() == 0
		
		
		# DEPENDENT TASKS SERIAL
		########################
		self._assert_async_dependent_tasks(p)
		
		
		# SINGLE TASK THREADED SYNC MODE
		################################
		# step one gear up - just one thread for now.
		num_threads = len(threading.enumerate())
		p.set_size(1)
		assert len(threading.enumerate()) == num_threads + 1
		# deleting the pool stops its threads - just to be sure ;)
		del(p)
		assert len(threading.enumerate()) == num_threads
		
		p = ThreadPool(1)
		assert len(threading.enumerate()) == num_threads + 1
		
		# here we go
		self._assert_single_task(p, False)
		
		
		
		# SINGLE TASK ASYNC MODE
		########################
		# two threads to compete for a single task
		p.set_size(2)
		self._assert_single_task(p, True)
		
		
		# DEPENDENT TASK ASYNC MODE
		###########################
		self._assert_async_dependent_tasks(p)
		
	
