"""Channel testing"""
from test.testlib import *
from task import *

from git.async.pool import *
from git.async.thread import terminate_threads
from git.async.util import cpu_count

import threading
import weakref
import time
import sys



class TestThreadPool(TestBase):
	
	max_threads = cpu_count()
	
	def _assert_single_task(self, p, async=False):
		"""Performs testing in a synchronized environment"""
		print >> sys.stderr, "Threadpool: Starting single task (async = %i) with %i threads" % (async, p.size())
		null_tasks = p.num_tasks()		# in case we had some before
		
		# add a simple task
		# it iterates n items
		ni = 1000
		assert ni % 2 == 0, "ni needs to be dividable by 2"
		assert ni % 4 == 0, "ni needs to be dividable by 4"
		
		make_task = lambda *args, **kwargs: make_iterator_task(ni, *args, **kwargs)
		
		task = make_task()
		
		assert p.num_tasks() == null_tasks
		rc = p.add_task(task)
		assert p.num_tasks() == 1 + null_tasks
		assert isinstance(rc, PoolReader)
		assert task._out_writer is not None
		
		# pull the result completely - we should get one task, which calls its 
		# function once. In sync mode, the order matches
		print "read(0)"
		items = rc.read()
		assert len(items) == ni
		task._assert(1, ni)
		if not async:
			assert items[0] == 0 and items[-1] == ni-1
		
		# as the task is done, it should have been removed - we have read everything
		assert task.is_done()
		del(rc)
		assert p.num_tasks() == null_tasks
		task = make_task()
		
		# pull individual items
		rc = p.add_task(task)
		assert p.num_tasks() == 1 + null_tasks
		st = time.time()
		print "read(1) * %i" % ni
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
		assert not task.is_done()
		assert p.num_tasks() == 1 + null_tasks
		del(rc)
		assert p.num_tasks() == null_tasks
		
		# test min count
		# if we query 1 item, it will prepare ni / 2
		task = make_task()
		task.min_count = ni / 2
		rc = p.add_task(task)
		print "read(1)"
		items = rc.read(1)
		assert len(items) == 1 and items[0] == 0			# processes ni / 2
		print "read(1)"
		items = rc.read(1)
		assert len(items) == 1 and items[0] == 1			# processes nothing
		# rest - it has ni/2 - 2 on the queue, and pulls ni-2
		# It wants too much, so the task realizes its done. The task
		# doesn't care about the items in its output channel
		nri = ni-2
		print "read(%i)" % nri
		items = rc.read(nri)
		assert len(items) == nri
		p.remove_task(task)
		assert p.num_tasks() == null_tasks
		task._assert(2, ni)						# two chunks, ni calls
		
		# its already done, gives us no more, its still okay to use it though
		# as a task doesn't have to be in the graph to allow reading its produced
		# items
		print "read(0) on closed"
		# it can happen that a thread closes the channel just a tiny fraction of time
		# after we check this, so the test fails, although it is nearly closed.
		# When we start reading, we should wake up once it sends its signal
		# assert task.is_closed()
		assert len(rc.read()) == 0
		
		# test chunking
		# we always want 4 chunks, these could go to individual nodes
		task = make_task()
		task.min_count = ni / 2				# restore previous value
		task.max_chunksize = ni / 4			# 4 chunks
		rc = p.add_task(task)
		
		# must read a specific item count
		# count is still at ni / 2 - here we want more than that
		# 2 steps with n / 4 items, + 1 step with n/4 items to get + 2
		nri = ni / 2 + 2
		print "read(%i) chunksize set" % nri
		items = rc.read(nri)
		assert len(items) == nri
		# have n / 4 - 2 items on queue, want n / 4 in first chunk, cause 1 processing
		# ( 4 in total ). Still want n / 4 - 2 in second chunk, causing another processing
		nri = ni / 2 - 2
		print "read(%i) chunksize set" % nri
		items = rc.read(nri)
		assert len(items) == nri
		
		task._assert( 5, ni)
		
		# delete the handle first, causing the task to be removed and to be set
		# done. We check for the set-done state later. Depending on the timing, 
		# The task is not yet set done when we are checking it because we were 
		# scheduled in before the flag could be set.
		del(rc)
		assert task.is_done()
		assert p.num_tasks() == null_tasks	# depleted
		
		# but this only hits if we want too many items, if we want less, it could 
		# still do too much - hence we set the min_count to the same number to enforce
		# at least ni / 4 items to be preocessed, no matter what we request
		task = make_task()
		task.min_count = None
		task.max_chunksize = ni / 4		# match previous setup
		rc = p.add_task(task)
		st = time.time()
		print "read(1) * %i, chunksize set" % ni
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
		assert p.remove_task(task) is p		# del manually this time
		assert p.num_tasks() == null_tasks
		
		# now with we set the minimum count to reduce the number of processing counts
		task = make_task()
		task.min_count = ni / 4
		task.max_chunksize = ni / 4		# match previous setup
		rc = p.add_task(task)
		print "read(1) * %i, min_count%i + chunksize" % (ni, task.min_count)
		for i in range(ni):
			items = rc.read(1)
			assert len(items) == 1
			if not async:
				assert items[0] == i
		# END for each item
		task._assert(ni / task.min_count, ni)
		del(rc)
		assert p.num_tasks() == null_tasks
		
		# test failure
		# on failure, the processing stops and the task is finished, keeping 
		# his error for later
		task = make_task()
		task.should_fail = True
		rc = p.add_task(task)
		print "read(0) with failure"
		assert len(rc.read()) == 0		# failure on first item
		
		assert isinstance(task.error(), AssertionError)
		assert task.is_done()			# on error, its marked done as well
		del(rc)
		assert p.num_tasks() == null_tasks
		
		# test failure after ni / 2 items
		# This makes sure it correctly closes the channel on failure to prevent blocking
		nri = ni/2
		task = make_task(TestFailureThreadTask, fail_after=ni/2)
		rc = p.add_task(task)
		assert len(rc.read()) == nri
		assert task.is_done()
		assert isinstance(task.error(), AssertionError)
		
		print >> sys.stderr, "done with everything"
		
		
		
	def _assert_async_dependent_tasks(self, pool):
		# includes failure in center task, 'recursive' orphan cleanup
		# This will also verify that the channel-close mechanism works
		# t1 -> t2 -> t3
	
		print >> sys.stderr, "Threadpool: starting async dependency test in %i threads" % pool.size()
		null_tasks = pool.num_tasks()
		ni = 1000
		count = 3
		aic = count + 2
		make_task = lambda *args, **kwargs: add_task_chain(pool, ni, count, *args, **kwargs)
		
		ts, rcs = make_task()
		assert len(ts) == aic
		assert len(rcs) == aic
		assert pool.num_tasks() == null_tasks + len(ts)
		
		# read(0)
		#########
		st = time.time()
		items = rcs[-1].read()
		elapsed = time.time() - st
		print len(items), ni
		assert len(items) == ni
		del(rcs)
		assert pool.num_tasks() == 0		# tasks depleted, all done, no handles
		# wait a tiny moment - there could still be something unprocessed on the 
		# queue, increasing the refcount
		time.sleep(0.15)
		assert sys.getrefcount(ts[-1]) == 2	# ts + call
		assert sys.getrefcount(ts[0]) == 2	# ts + call
		print >> sys.stderr, "Dependent Tasks: evaluated %i items of %i dependent in %f s ( %i items / s )" % (ni, aic, elapsed, ni / elapsed)
		
		
		# read(1)
		#########
		ts, rcs = make_task()
		st = time.time()
		for i in xrange(ni):
			items = rcs[-1].read(1)
			assert len(items) == 1
		# END for each item to pull
		elapsed_single = time.time() - st
		# another read yields nothing, its empty
		assert len(rcs[-1].read()) == 0
		print >> sys.stderr, "Dependent Tasks: evaluated %i items with read(1) of %i dependent in %f s ( %i items / s )" % (ni, aic, elapsed_single, ni / elapsed_single)
		
		
		# read with min-count size
		###########################
		# must be faster, as it will read ni / 4 chunks
		# Its enough to set one task, as it will force all others in the chain 
		# to min_size as well.
		ts, rcs = make_task()
		assert pool.num_tasks() == len(ts)
		nri = ni / 4
		ts[-1].min_count = nri
		st = time.time()
		for i in xrange(ni):
			items = rcs[-1].read(1)
			assert len(items) == 1
		# END for each item to read
		elapsed_minsize = time.time() - st
		# its empty
		assert len(rcs[-1].read()) == 0
		print >> sys.stderr, "Dependent Tasks: evaluated %i items with read(1), min_size=%i, of %i dependent in %f s ( %i items / s )" % (ni, nri, aic, elapsed_minsize, ni / elapsed_minsize)
		
		# it should have been a bit faster at least, and most of the time it is
		# Sometimes, its not, mainly because:
		# * The test tasks lock a lot, hence they slow down the system
		# * Each read will still trigger the pool to evaluate, causing some overhead
		#   even though there are enough items on the queue in that case. Keeping 
		#	track of the scheduled items helped there, but it caused further inacceptable 
		#	slowdown
		# assert elapsed_minsize < elapsed_single
			
		
		# read with failure
		###################
		# it should recover and give at least fail_after items
		# t1 -> x -> t3
		fail_after = ni/2
		ts, rcs = make_task(fail_setup=[(0, fail_after)])
		items = rcs[-1].read()
		assert len(items) == fail_after
		
			
		# MULTI-POOL
		# If two pools are connected, this shold work as well.
		# The second one has just one more thread
		ts, rcs = make_task()
		
		# connect verifier channel as feeder of the second pool
		p2 = ThreadPool(0)		# don't spawn new threads, they have the tendency not to wake up on mutexes
		assert p2.size() == 0
		p2ts, p2rcs = add_task_chain(p2, ni, count, feeder_channel=rcs[-1], id_offset=count)
		assert p2ts[0] is None		# we have no feeder task
		assert rcs[-1].pool_ref()() is pool		# it didnt change the pool
		assert rcs[-1] is p2ts[1].reader()
		assert p2.num_tasks() == len(p2ts)-1	# first is None
		
		# reading from the last one will evaluate all pools correctly
		print "read(0) multi-pool"
		st = time.time()
		items = p2rcs[-1].read()
		elapsed = time.time() - st
		assert len(items) == ni
		
		print >> sys.stderr, "Dependent Tasks: evaluated 2 connected pools and %i items with read(0), of %i dependent tasks in %f s ( %i items / s )" % (ni, aic + aic-1, elapsed, ni / elapsed)
		
		
		# loose the handles of the second pool to allow others to go as well
		del(p2rcs); del(p2ts)
		assert p2.num_tasks() == 0
		
		# now we lost our old handles as well, and the tasks go away
		ts, rcs = make_task()
		assert pool.num_tasks() == len(ts)
		
		p2ts, p2rcs = add_task_chain(p2, ni, count, feeder_channel=rcs[-1], id_offset=count)
		assert p2.num_tasks() == len(p2ts) - 1 
		
		# Test multi-read(1)
		print "read(1) * %i" % ni
		reader = rcs[-1]
		st = time.time()
		for i in xrange(ni):
			items = reader.read(1)
			assert len(items) == 1
		# END for each item to get
		elapsed = time.time() - st
		del(reader)		# decrement refcount
		
		print >> sys.stderr, "Dependent Tasks: evaluated 2 connected pools and %i items with read(1), of %i dependent tasks in %f s ( %i items / s )" % (ni, aic + aic-1, elapsed, ni / elapsed)
		
		# another read is empty
		assert len(rcs[-1].read()) == 0
		
		# now that both are connected, I can drop my handle to the reader
		# without affecting the task-count, but whats more important: 
		# They remove their tasks correctly once we drop our references in the
		# right order
		del(p2ts)
		assert p2rcs[0] is rcs[-1]
		del(p2rcs)
		assert p2.num_tasks() == 0
		del(p2)
		
		assert pool.num_tasks() == null_tasks + len(ts)
		
		
		del(ts)
		del(rcs)
		
		assert pool.num_tasks() == null_tasks 
		
		
		# ASSERTION: We already tested that one pool behaves correctly when an error
		# occours - if two pools handle their ref-counts correctly, which they
		# do if we are here, then they should handle errors happening during 
		# the task processing as expected as well. Hence we can safe this here
		
	
	
	@terminate_threads
	def test_base(self):
		max_wait_attempts = 3
		sleep_time = 0.1
		for mc in range(max_wait_attempts):
			# wait for threads to die
			if len(threading.enumerate()) != 1:
				time.sleep(sleep_time)
		# END for each attempt
		assert len(threading.enumerate()) == 1, "Waited %f s for threads to die, its still alive" % (max_wait_attempts, sleep_time) 
		
		p = ThreadPool()
		
		# default pools have no workers
		assert p.size() == 0
		
		# increase and decrease the size
		num_threads = len(threading.enumerate())
		for i in range(self.max_threads):
			p.set_size(i)
			assert p.size() == i
			assert len(threading.enumerate()) == num_threads + i
			
		for i in range(self.max_threads, -1, -1):
			p.set_size(i)
			assert p.size() == i
		
		assert p.size() == 0
		# threads should be killed already, but we let them a tiny amount of time
		# just to be sure
		time.sleep(0.05)
		assert len(threading.enumerate()) == num_threads
		
		# SINGLE TASK SERIAL SYNC MODE
		##############################
		# put a few unrelated tasks that we forget about - check ref counts and cleanup
		t1, t2 = TestThreadTask(iter(list()), "nothing1", None), TestThreadTask(iter(list()), "nothing2", None)
		urc1 = p.add_task(t1)
		urc2 = p.add_task(t2)
		assert p.num_tasks() == 2
		
		## SINGLE TASK #################
		self._assert_single_task(p, False)
		assert p.num_tasks() == 2
		del(urc1)
		assert p.num_tasks() == 1
		
		p.remove_task(t2)
		assert p.num_tasks() == 0
		assert sys.getrefcount(t2) == 2
		
		t3 = TestChannelThreadTask(urc2, "channel", None)
		urc3 = p.add_task(t3)
		assert p.num_tasks() == 1
		del(urc3)
		assert p.num_tasks() == 0
		assert sys.getrefcount(t3) == 2
		
		
		# DEPENDENT TASKS SYNC MODE
		###########################
		self._assert_async_dependent_tasks(p)
		
		
		# SINGLE TASK THREADED ASYNC MODE ( 1 thread )
		##############################################
		# step one gear up - just one thread for now.
		p.set_size(1)
		assert p.size() == 1
		assert len(threading.enumerate()) == num_threads + 1
		# deleting the pool stops its threads - just to be sure ;)
		# Its not synchronized, hence we wait a moment
		del(p)
		time.sleep(0.05)
		assert len(threading.enumerate()) == num_threads
		
		p = ThreadPool(1)
		assert len(threading.enumerate()) == num_threads + 1
		
		# here we go
		self._assert_single_task(p, True)
		
		
		
		# SINGLE TASK ASYNC MODE ( 2 threads )
		######################################
		# two threads to compete for a single task
		p.set_size(2)
		self._assert_single_task(p, True)
		
		# real stress test-  should be native on every dual-core cpu with 2 hardware
		# threads per core
		p.set_size(4)
		self._assert_single_task(p, True)
		
		
		# DEPENDENT TASK ASYNC MODE
		###########################
		self._assert_async_dependent_tasks(p)
		
		print >> sys.stderr, "Done with everything"
		
