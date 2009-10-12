# test_blob.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import time
from test.testlib import *
from git import *

class TestBlob(object):
	def setup(self):
		self.repo = Repo(GIT_REPO)
	
	@patch_object(Git, '_call_process')
	def test_should_return_blob_contents(self, git):
		git.return_value = fixture('cat_file_blob')
		blob = Blob(self.repo, **{'id': 'abc'})
		assert_equal("Hello world", blob.data)
		assert_true(git.called)
		assert_equal(git.call_args, (('cat_file', 'abc'), {'p': True, 'with_raw_output': True}))

	@patch_object(Git, '_call_process')
	def test_should_return_blob_contents_with_newline(self, git):
		git.return_value = fixture('cat_file_blob_nl')
		blob = Blob(self.repo, **{'id': 'abc'})
		assert_equal("Hello world\n", blob.data)
		assert_true(git.called)
		assert_equal(git.call_args, (('cat_file', 'abc'), {'p': True, 'with_raw_output': True}))
	
	@patch_object(Git, '_call_process')
	def test_should_cache_data(self, git):
		git.return_value = fixture('cat_file_blob')
		bid = '787b92b63f629398f3d2ceb20f7f0c2578259e84'
		blob = Blob(self.repo, bid)
		blob.data
		blob.data
		assert_true(git.called)
		assert_equal(git.call_count, 1)
		assert_equal(git.call_args, (('cat_file', bid), {'p': True, 'with_raw_output': True}))

	@patch_object(Git, '_call_process')
	def test_should_return_file_size(self, git):
		git.return_value = fixture('cat_file_blob_size')
		blob = Blob(self.repo, **{'id': 'abc'})
		assert_equal(11, blob.size)
		assert_true(git.called)
		assert_equal(git.call_args, (('cat_file', 'abc'), {'s': True}))

	@patch_object(Git, '_call_process')
	def test_should_cache_file_size(self, git):
		git.return_value = fixture('cat_file_blob_size')
		blob = Blob(self.repo, **{'id': 'abc'})
		assert_equal(11, blob.size)
		assert_equal(11, blob.size)
		assert_true(git.called)
		assert_equal(git.call_count, 1)
		assert_equal(git.call_args, (('cat_file', 'abc'), {'s': True}))
  
	def test_mime_type_should_return_mime_type_for_known_types(self):
		blob = Blob(self.repo, **{'id': 'abc', 'path': 'foo.png'})
		assert_equal("image/png", blob.mime_type)
  
	def test_mime_type_should_return_text_plain_for_unknown_types(self):
		blob = Blob(self.repo, **{'id': 'abc','path': 'something'})
		assert_equal("text/plain", blob.mime_type)
  
	def test_should_return_appropriate_representation(self):
		blob = Blob(self.repo, **{'id': 'abc'})
		assert_equal('<git.Blob "abc">', repr(blob))
