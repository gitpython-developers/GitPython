# test_utils.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import tempfile

from git.test.lib import *
from git.util import *
from git.objects.util import *
from git import *
from git.cmd import dashify

import time


class TestUtils(TestBase):
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
		
	def test_user_id(self):
		assert '@' in get_user_id()
		
	def test_parse_date(self):
		# test all supported formats
		def assert_rval(rval, veri_time, offset=0):
			assert len(rval) == 2
			assert isinstance(rval[0], int) and isinstance(rval[1], int)
			assert rval[0] == veri_time
			assert rval[1] == offset
			
			# now that we are here, test our conversion functions as well
			utctz = altz_to_utctz_str(offset)
			assert isinstance(utctz, basestring)
			assert utctz_to_altz(verify_utctz(utctz)) == offset
		# END assert rval utility
		
		rfc = ("Thu, 07 Apr 2005 22:13:11 +0000", 0)
		iso = ("2005-04-07T22:13:11 -0200", 7200)
		iso2 = ("2005-04-07 22:13:11 +0400", -14400)
		iso3 = ("2005.04.07 22:13:11 -0000", 0)
		alt = ("04/07/2005 22:13:11", 0)
		alt2 = ("07.04.2005 22:13:11", 0)
		veri_time = 1112904791		# the time this represents
		for date, offset in (rfc, iso, iso2, iso3, alt, alt2):
			assert_rval(parse_date(date), veri_time, offset)
		# END for each date type
		
		# and failure
		self.failUnlessRaises(ValueError, parse_date, 'invalid format')
		self.failUnlessRaises(ValueError, parse_date, '123456789 -02000')
		self.failUnlessRaises(ValueError, parse_date, ' 123456789 -0200')
		
	def test_actor(self):
		for cr in (None, self.rorepo.config_reader()):
			assert isinstance(Actor.committer(cr), Actor)
			assert isinstance(Actor.author(cr), Actor)
		#END assure config reader is handled
