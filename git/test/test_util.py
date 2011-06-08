# test_utils.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import tempfile

from lib import TestBase
from git.util import *
from git.objects.util import *
from git import *
from git.cmd import dashify

import time

from git.util import (
	to_hex_sha, 
	to_bin_sha, 
	NULL_HEX_SHA, 
	LockedFD, 
	Actor,
	IterableList
	)


class TestIterableMember(object):
	"""A member of an iterable list"""
	__slots__ = ("name", "prefix_name")
	
	def __init__(self, name):
		self.name = name
		self.prefix_name = name
		

class TestUtils(TestBase):
	def setup(self):
		self.testdict = {
			"string":	"42",
			"int":		42,
			"array":	[ 42 ],
		}

	def test_it_should_dashify(self):
		assert 'this-is-my-argument' == dashify('this_is_my_argument')
		assert 'foo' == dashify('foo')
		
		
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
		
	def test_basics(self):
		assert to_hex_sha(NULL_HEX_SHA) == NULL_HEX_SHA
		assert len(to_bin_sha(NULL_HEX_SHA)) == 20
		assert to_hex_sha(to_bin_sha(NULL_HEX_SHA)) == NULL_HEX_SHA
		
	def _cmp_contents(self, file_path, data):
		# raise if data from file at file_path 
		# does not match data string
		fp = open(file_path, "rb")
		try:
			assert fp.read() == data
		finally:
			fp.close()
		
	def test_lockedfd(self):
		my_file = tempfile.mktemp()
		orig_data = "hello"
		new_data = "world"
		my_file_fp = open(my_file, "wb")
		my_file_fp.write(orig_data)
		my_file_fp.close()
		
		try:
			lfd = LockedFD(my_file)
			lockfilepath = lfd._lockfilepath() 
			
			# cannot end before it was started
			self.failUnlessRaises(AssertionError, lfd.rollback)
			self.failUnlessRaises(AssertionError, lfd.commit)
			
			# open for writing
			assert not os.path.isfile(lockfilepath)
			wfd = lfd.open(write=True)
			assert lfd._fd is wfd
			assert os.path.isfile(lockfilepath)
			
			# write data and fail
			os.write(wfd, new_data)
			lfd.rollback()
			assert lfd._fd is None
			self._cmp_contents(my_file, orig_data)
			assert not os.path.isfile(lockfilepath)
			
			# additional call doesnt fail
			lfd.commit()
			lfd.rollback()
			
			# test reading
			lfd = LockedFD(my_file)
			rfd = lfd.open(write=False)
			assert os.read(rfd, len(orig_data)) == orig_data
			
			assert os.path.isfile(lockfilepath)
			# deletion rolls back
			del(lfd)
			assert not os.path.isfile(lockfilepath)
			
			
			# write data - concurrently
			lfd = LockedFD(my_file)
			olfd = LockedFD(my_file)
			assert not os.path.isfile(lockfilepath)
			wfdstream = lfd.open(write=True, stream=True)		# this time as stream
			assert os.path.isfile(lockfilepath)
			# another one fails
			self.failUnlessRaises(IOError, olfd.open)
			
			wfdstream.write(new_data)
			lfd.commit()
			assert not os.path.isfile(lockfilepath)
			self._cmp_contents(my_file, new_data)
			
			# could test automatic _end_writing on destruction
		finally:
			os.remove(my_file)
		# END final cleanup
		
		# try non-existing file for reading
		lfd = LockedFD(tempfile.mktemp())
		try:
			lfd.open(write=False)
		except OSError:
			assert not os.path.exists(lfd._lockfilepath())
		else:
			self.fail("expected OSError")
		# END handle exceptions

	def test_iterable_list(self):
		for args in (('name',), ('name', 'prefix_')):
			l = IterableList('name')
			
			m1 = TestIterableMember('one')
			m2 = TestIterableMember('two')
			
			l.extend((m1, m2))
			
			assert len(l) == 2
			
			# contains works with name and identity
			assert m1.name in l
			assert m2.name in l
			assert m2 in l
			assert m2 in l
			assert 'invalid' not in l
			
			# with string index
			assert l[m1.name] is m1
			assert l[m2.name] is m2
			
			# with int index
			assert l[0] is m1
			assert l[1] is m2
			
			# with getattr
			assert l.one is m1
			assert l.two is m2
			
			# test exceptions
			self.failUnlessRaises(AttributeError, getattr, l, 'something')
			self.failUnlessRaises(IndexError, l.__getitem__, 'something')
			
			# delete by name and index
			self.failUnlessRaises(IndexError, l.__delitem__, 'something')
			del(l[m2.name])
			assert len(l) == 1
			assert m2.name not in l and m1.name in l
			del(l[0])
			assert m1.name not in l
			assert len(l) == 0
			
			self.failUnlessRaises(IndexError, l.__delitem__, 0)
			self.failUnlessRaises(IndexError, l.__delitem__, 'something')
		#END for each possible mode
	

class TestActor(TestBase):
    def test_from_string_should_separate_name_and_email(self):
        a = Actor._from_string("Michael Trier <mtrier@example.com>")
        assert "Michael Trier" == a.name
        assert "mtrier@example.com" == a.email
        
        # base type capabilities
        assert a == a
        assert not ( a != a )
        m = set()
        m.add(a)
        m.add(a)
        assert len(m) == 1

    def test_from_string_should_handle_just_name(self):
        a = Actor._from_string("Michael Trier")
        assert "Michael Trier" == a.name
        assert None == a.email

    def test_should_display_representation(self):
        a = Actor._from_string("Michael Trier <mtrier@example.com>")
        assert '<git.Actor "Michael Trier <mtrier@example.com>">' == repr(a)

    def test_str_should_alias_name(self):
        a = Actor._from_string("Michael Trier <mtrier@example.com>")
        assert a.name == str(a)
