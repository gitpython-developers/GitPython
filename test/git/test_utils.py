# test_utils.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import tempfile

from test.testlib import *
from git.utils import *
from git import *
from git.cmd import dashify
import time


class TestUtils(TestCase):
	def setup(self):
		self.testdict = {
			"string":	"42",
			"int":		42,
			"array":	[ 42 ],
		}

	def test_it_should_dashify(self):
		assert_equal('this-is-my-argument', dashify('this_is_my_argument'))
		assert_equal('foo', dashify('foo'))
		
		
	def test_lock_file(self):
		my_file = tempfile.mktemp()
		lock_file = LockFile(my_file)
		assert not lock_file._has_lock()
		# release lock we don't have  - fine
		lock_file._release_lock()
		
		# get lock
		lock_file._obtain_lock_or_raise()
		assert lock_file._has_lock()
		
		# concurrent access
		other_lock_file = LockFile(my_file)
		assert not other_lock_file._has_lock()
		self.failUnlessRaises(IOError, other_lock_file._obtain_lock_or_raise)
		
		lock_file._release_lock()
		assert not lock_file._has_lock()
		
		other_lock_file._obtain_lock_or_raise()
		self.failUnlessRaises(IOError, lock_file._obtain_lock_or_raise)
		
		# auto-release on destruction
		del(other_lock_file)
		lock_file._obtain_lock_or_raise()
		lock_file._release_lock()
		
	def test_blocking_lock_file(self):
		my_file = tempfile.mktemp()
		lock_file = BlockingLockFile(my_file)
		lock_file._obtain_lock()
		
		# next one waits for the lock
		start = time.time()
		wait_time = 0.1
		wait_lock = BlockingLockFile(my_file, 0.05, wait_time)
		self.failUnlessRaises(IOError, wait_lock._obtain_lock)
		elapsed = time.time() - start
		assert elapsed <= wait_time + 0.02	# some extra time it may cost
		
	def _cmp_contents(self, file_path, data):
		# raise if data from file at file_path 
		# does not match data string
		fp = open(file_path, "rb")
		try:
			assert fp.read() == data
		finally:
			fp.close()
		
	def test_safe_operation(self):
		my_file = tempfile.mktemp()
		orig_data = "hello"
		new_data = "world"
		my_file_fp = open(my_file, "wb")
		my_file_fp.write(orig_data)
		my_file_fp.close()
		
		try:
			cwrite = ConcurrentWriteOperation(my_file)
			
			# didn't start writing, doesnt matter
			cwrite._end_writing(False)
			cwrite._end_writing(True)
			assert not cwrite._is_writing()
			
			# write data and fail
			stream = cwrite._begin_writing()
			assert cwrite._is_writing()
			stream.write(new_data)
			cwrite._end_writing(successful=False)
			self._cmp_contents(my_file, orig_data)
			assert not os.path.exists(stream.name)
			
			# write data - concurrently
			ocwrite = ConcurrentWriteOperation(my_file)
			stream = cwrite._begin_writing()
			self.failUnlessRaises(IOError, ocwrite._begin_writing)
			
			stream.write("world")
			cwrite._end_writing(successful=True)
			self._cmp_contents(my_file, new_data)
			assert not os.path.exists(stream.name)
				
			# could test automatic _end_writing on destruction
		finally:
			os.remove(my_file)
		# END final cleanup
		
		
		
		
