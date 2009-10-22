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
		
	def test_safe_operation(self):
		self.fail("todo")
