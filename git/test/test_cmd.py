# test_git.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os, sys
from git.test.lib import (
							TestBase, 
							patch_object, 
							raises,
							assert_equal,
							assert_true,
							assert_match,
							fixture_path
						)
from git import Git, GitCommandError

class TestGit(TestBase):
	
	@classmethod
	def setUpAll(cls):
		super(TestGit, cls).setUpAll()
		cls.git = Git(cls.rorepo.working_dir)

	@patch_object(Git, 'execute')
	def test_call_process_calls_execute(self, git):
		git.return_value = ''
		self.git.version()
		assert_true(git.called)
		assert_equal(git.call_args, ((['git', 'version'],), {}))

	@raises(GitCommandError)
	def test_it_raises_errors(self):
		self.git.this_does_not_exist()


	def test_it_transforms_kwargs_into_git_command_arguments(self):
		assert_equal(["-s"], self.git.transform_kwargs(**{'s': True}))
		assert_equal(["-s5"], self.git.transform_kwargs(**{'s': 5}))

		assert_equal(["--max-count"], self.git.transform_kwargs(**{'max_count': True}))
		assert_equal(["--max-count=5"], self.git.transform_kwargs(**{'max_count': 5}))

		assert_equal(["-s", "-t"], self.git.transform_kwargs(**{'s': True, 't': True}))

	def test_it_executes_git_to_shell_and_returns_result(self):
		assert_match('^git version [\d\.]{2}.*$', self.git.execute(["git","version"]))

	def test_it_accepts_stdin(self):
		filename = fixture_path("cat_file_blob")
		fh = open(filename, 'r')
		assert_equal("70c379b63ffa0795fdbfbc128e5a2818397b7ef8",
					 self.git.hash_object(istream=fh, stdin=True))
		fh.close()

	@patch_object(Git, 'execute')
	def test_it_ignores_false_kwargs(self, git):
		# this_should_not_be_ignored=False implies it *should* be ignored
		output = self.git.version(pass_this_kwarg=False)
		assert_true("pass_this_kwarg" not in git.call_args[1])
		
	def test_persistent_cat_file_command(self):
		# read header only
		import subprocess as sp
		hexsha = "b2339455342180c7cc1e9bba3e9f181f7baa5167"
		g = self.git.cat_file(batch_check=True, istream=sp.PIPE,as_process=True)
		g.stdin.write("b2339455342180c7cc1e9bba3e9f181f7baa5167\n")
		g.stdin.flush()
		obj_info = g.stdout.readline()
		
		# read header + data
		g = self.git.cat_file(batch=True, istream=sp.PIPE,as_process=True)
		g.stdin.write("b2339455342180c7cc1e9bba3e9f181f7baa5167\n")
		g.stdin.flush()
		obj_info_two = g.stdout.readline()
		assert obj_info == obj_info_two
		
		# read data - have to read it in one large chunk
		size = int(obj_info.split()[2])
		data = g.stdout.read(size)
		terminating_newline = g.stdout.read(1)
		
		# now we should be able to read a new object
		g.stdin.write("b2339455342180c7cc1e9bba3e9f181f7baa5167\n")
		g.stdin.flush()
		assert g.stdout.readline() == obj_info
		
		
		# same can be achived using the respective command functions
		hexsha, typename, size =  self.git.get_object_header(hexsha)
		hexsha, typename_two, size_two, data = self.git.get_object_data(hexsha)
		assert typename == typename_two and size == size_two
		
	def test_version(self):
		v = self.git.version_info
		assert isinstance(v, tuple)
		for n in v:
			assert isinstance(n, int)
		#END verify number types
		
	def test_cmd_override(self):
		prev_cmd = self.git.GIT_PYTHON_GIT_EXECUTABLE
		try:
			# set it to something that doens't exist, assure it raises
			type(self.git).GIT_PYTHON_GIT_EXECUTABLE = os.path.join("some", "path", "which", "doesn't", "exist", "gitbinary")
			self.failUnlessRaises(OSError, self.git.version)
		finally:
			type(self.git).GIT_PYTHON_GIT_EXECUTABLE = prev_cmd
		#END undo adjustment
