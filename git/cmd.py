# cmd.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os, sys
from util import (
					LazyMixin, 
					stream_copy
				)
from exc import GitCommandError

from subprocess import (
							call, 
							Popen,
							PIPE
						)

execute_kwargs = ('istream', 'with_keep_cwd', 'with_extended_output',
				  'with_exceptions', 'as_process', 
				  'output_stream' )

__all__ = ('Git', )

def dashify(string):
	return string.replace('_', '-')


class Git(LazyMixin):
	"""
	The Git class manages communication with the Git binary.
	
	It provides a convenient interface to calling the Git binary, such as in::
	
	 g = Git( git_dir )
	 g.init()					# calls 'git init' program
	 rval = g.ls_files()		# calls 'git ls-files' program
	
	``Debugging``
		Set the GIT_PYTHON_TRACE environment variable print each invocation 
		of the command to stdout.
		Set its value to 'full' to see details about the returned values.
	"""
	__slots__ = ("_working_dir", "cat_file_all", "cat_file_header", "_version_info")
	
	# CONFIGURATION
	# The size in bytes read from stdout when copying git's output to another stream
	max_chunk_size = 1024*64
	
	# Enables debugging of GitPython's git commands
	GIT_PYTHON_TRACE = os.environ.get("GIT_PYTHON_TRACE", False)
	
	# Provide the full path to the git executable. Otherwise it assumes git is in the path
	GIT_PYTHON_GIT_EXECUTABLE = os.environ.get("GIT_PYTHON_GIT_EXECUTABLE", 'git')
	
	
	class AutoInterrupt(object):
		"""Kill/Interrupt the stored process instance once this instance goes out of scope. It is 
		used to prevent processes piling up in case iterators stop reading.
		Besides all attributes are wired through to the contained process object.
		
		The wait method was overridden to perform automatic status code checking
		and possibly raise."""
		__slots__= ("proc", "args")
		
		def __init__(self, proc, args ):
			self.proc = proc
			self.args = args
			
		def __del__(self):
			# did the process finish already so we have a return code ?
			if self.proc.poll() is not None:
				return
				
			# can be that nothing really exists anymore ... 
			if os is None:
				return
				
			# try to kill it
			try:
				os.kill(self.proc.pid, 2)	# interrupt signal
			except AttributeError:
				# try windows 
				# for some reason, providing None for stdout/stderr still prints something. This is why 
				# we simply use the shell and redirect to nul. Its slower than CreateProcess, question 
				# is whether we really want to see all these messages. Its annoying no matter what.
				call(("TASKKILL /F /T /PID %s 2>nul 1>nul" % str(self.proc.pid)), shell=True)
			# END exception handling 
			
		def __getattr__(self, attr):
			return getattr(self.proc, attr)
			
		def wait(self):
			"""Wait for the process and return its status code. 
			
			:raise GitCommandError: if the return status is not 0"""
			status = self.proc.wait()
			if status != 0:
				raise GitCommandError(self.args, status, self.proc.stderr.read())
			# END status handling 
			return status
	# END auto interrupt
	
	class CatFileContentStream(object):
		"""Object representing a sized read-only stream returning the contents of 
		an object.
		It behaves like a stream, but counts the data read and simulates an empty 
		stream once our sized content region is empty.
		If not all data is read to the end of the objects's lifetime, we read the 
		rest to assure the underlying stream continues to work"""
		
		__slots__ = ('_stream', '_nbr', '_size')
		
		def __init__(self, size, stream):
			self._stream = stream
			self._size = size
			self._nbr = 0			# num bytes read
			
			# special case: if the object is empty, has null bytes, get the 
			# final newline right away.
			if size == 0:
				stream.read(1)
			# END handle empty streams
			
		def read(self, size=-1):
			bytes_left = self._size - self._nbr
			if bytes_left == 0:
				return ''
			if size > -1:
				# assure we don't try to read past our limit
				size = min(bytes_left, size)
			else:
				# they try to read all, make sure its not more than what remains
				size = bytes_left
			# END check early depletion
			data = self._stream.read(size)
			self._nbr += len(data)
			
			# check for depletion, read our final byte to make the stream usable by others
			if self._size - self._nbr == 0:
				self._stream.read(1)	# final newline
			# END finish reading
			return data
			
		def readline(self, size=-1):
			if self._nbr == self._size:
				return ''
			
			# clamp size to lowest allowed value
			bytes_left = self._size - self._nbr
			if size > -1:
				size = min(bytes_left, size)
			else:
				size = bytes_left
			# END handle size
			
			data = self._stream.readline(size)
			self._nbr += len(data)
			
			# handle final byte
			if self._size - self._nbr == 0:
				self._stream.read(1)
			# END finish reading
			
			return data
			
		def readlines(self, size=-1):
			if self._nbr == self._size:
				return list()
			
			# leave all additional logic to our readline method, we just check the size
			out = list()
			nbr = 0
			while True:
				line = self.readline()
				if not line:
					break
				out.append(line)
				if size > -1:
					nbr += len(line)
					if nbr > size:
						break
				# END handle size constraint
			# END readline loop
			return out
			
		def __iter__(self):
			return self
			
		def next(self):
			line = self.readline()
			if not line:
				raise StopIteration
			return line
			
		def __del__(self):
			bytes_left = self._size - self._nbr
			if bytes_left:
				# read and discard - seeking is impossible within a stream
				# includes terminating newline
				self._stream.read(bytes_left + 1)
			# END handle incomplete read
	
	
	def __init__(self, working_dir=None):
		"""Initialize this instance with:
		
		:param working_dir:
		   Git directory we should work in. If None, we always work in the current 
		   directory as returned by os.getcwd().
		   It is meant to be the working tree directory if available, or the 
		   .git directory in case of bare repositories."""
		super(Git, self).__init__()
		self._working_dir = working_dir
		
		# cached command slots
		self.cat_file_header = None
		self.cat_file_all = None

	def __getattr__(self, name):
		"""A convenience method as it allows to call the command as if it was 
		an object.
		:return: Callable object that will execute call _call_process with your arguments."""
		if name[0] == '_':
			return LazyMixin.__getattr__(self, name)
		return lambda *args, **kwargs: self._call_process(name, *args, **kwargs)

	def _set_cache_(self, attr):
		if attr == '_version_info':
			# We only use the first 4 numbers, as everthing else could be strings in fact (on windows)
			version_numbers = self._call_process('version').split(' ')[2]
			self._version_info = tuple(int(n) for n in version_numbers.split('.')[:4])
		else:
			super(Git, self)._set_cache_(attr)
		#END handle version info
			

	@property
	def working_dir(self):
		""":return: Git directory we are working on"""
		return self._working_dir
		
	@property
	def version_info(self):
		"""
		:return: tuple(int, int, int, int) tuple with integers representing the major, minor
			and additional version numbers as parsed from git version.
			This value is generated on demand and is cached"""
		return self._version_info

	def execute(self, command,
				istream=None,
				with_keep_cwd=False,
				with_extended_output=False,
				with_exceptions=True,
				as_process=False, 
				output_stream=None, 
				**subprocess_kwargs
				):
		"""Handles executing the command on the shell and consumes and returns
		the returned information (stdout)

		:param command:
			The command argument list to execute.
			It should be a string, or a sequence of program arguments. The
			program to execute is the first item in the args sequence or string.

		:param istream:
			Standard input filehandle passed to subprocess.Popen.

		:param with_keep_cwd:
			Whether to use the current working directory from os.getcwd().
			The cmd otherwise uses its own working_dir that it has been initialized
			with if possible.

		:param with_extended_output:
			Whether to return a (status, stdout, stderr) tuple.

		:param with_exceptions:
			Whether to raise an exception when git returns a non-zero status.

		:param as_process:
			Whether to return the created process instance directly from which 
			streams can be read on demand. This will render with_extended_output and 
			with_exceptions ineffective - the caller will have 
			to deal with the details himself.
			It is important to note that the process will be placed into an AutoInterrupt
			wrapper that will interrupt the process once it goes out of scope. If you 
			use the command in iterators, you should pass the whole process instance 
			instead of a single stream.
			
		:param output_stream:
			If set to a file-like object, data produced by the git command will be 
			output to the given stream directly.
			This feature only has any effect if as_process is False. Processes will
			always be created with a pipe due to issues with subprocess.
			This merely is a workaround as data will be copied from the 
			output pipe to the given output stream directly.
			
		:param subprocess_kwargs:
			Keyword arguments to be passed to subprocess.Popen. Please note that 
			some of the valid kwargs are already set by this method, the ones you 
			specify may not be the same ones.
			
		:return:
			* str(output) if extended_output = False (Default)
			* tuple(int(status), str(stdout), str(stderr)) if extended_output = True
			 
			if ouput_stream is True, the stdout value will be your output stream:
			* output_stream if extended_output = False
			* tuple(int(status), output_stream, str(stderr)) if extended_output = True
			
		:raise GitCommandError:
		
		:note:
		   If you add additional keyword arguments to the signature of this method, 
		   you must update the execute_kwargs tuple housed in this module."""
		if self.GIT_PYTHON_TRACE and not self.GIT_PYTHON_TRACE == 'full':
			print ' '.join(command)

		# Allow the user to have the command executed in their working dir.
		if with_keep_cwd or self._working_dir is None:
		  cwd = os.getcwd()
		else:
		  cwd=self._working_dir
		  
		# Start the process
		proc = Popen(command,
						cwd=cwd,
						stdin=istream,
						stderr=PIPE,
						stdout=PIPE,
						close_fds=(os.name=='posix'),# unsupported on linux
						**subprocess_kwargs
						)
		if as_process:
			return self.AutoInterrupt(proc, command)
		
		# Wait for the process to return
		status = 0
		stdout_value = ''
		stderr_value = ''
		try:
			if output_stream is None:
				stdout_value, stderr_value = proc.communicate() 
				# strip trailing "\n"
				if stdout_value.endswith("\n"):
					stdout_value = stdout_value[:-1]
				if stderr_value.endswith("\n"):
					stderr_value = stderr_value[:-1]
				status = proc.returncode
			else:
				stream_copy(proc.stdout, output_stream, self.max_chunk_size)
				stdout_value = output_stream
				stderr_value = proc.stderr.read()
				# strip trailing "\n"
				if stderr_value.endswith("\n"):
					stderr_value = stderr_value[:-1]
				status = proc.wait()
			# END stdout handling
		finally:
			proc.stdout.close()
			proc.stderr.close()

		if self.GIT_PYTHON_TRACE == 'full':
			cmdstr = " ".join(command)
			if stderr_value:
				print "%s -> %d; stdout: '%s'; stderr: '%s'" % (cmdstr, status, stdout_value, stderr_value)
			elif stdout_value:
				print "%s -> %d; stdout: '%s'" % (cmdstr, status, stdout_value)
			else:
				print "%s -> %d" % (cmdstr, status)
		# END handle debug printing

		if with_exceptions and status != 0:
			raise GitCommandError(command, status, stderr_value)

		# Allow access to the command's status code
		if with_extended_output:
			return (status, stdout_value, stderr_value)
		else:
			return stdout_value

	def transform_kwargs(self, **kwargs):
		"""Transforms Python style kwargs into git command line options."""
		args = list()
		for k, v in kwargs.items():
			if len(k) == 1:
				if v is True:
					args.append("-%s" % k)
				elif type(v) is not bool:
					args.append("-%s%s" % (k, v))
			else:
				if v is True:
					args.append("--%s" % dashify(k))
				elif type(v) is not bool:
					args.append("--%s=%s" % (dashify(k), v))
		return args

	@classmethod
	def __unpack_args(cls, arg_list):
		if not isinstance(arg_list, (list,tuple)):
			return [ str(arg_list) ]
			
		outlist = list()
		for arg in arg_list:
			if isinstance(arg_list, (list, tuple)):
				outlist.extend(cls.__unpack_args( arg ))
			# END recursion 
			else:
				outlist.append(str(arg))
		# END for each arg
		return outlist

	def _call_process(self, method, *args, **kwargs):
		"""Run the given git command with the specified arguments and return
		the result as a String

		:param method:
			is the command. Contained "_" characters will be converted to dashes,
			such as in 'ls_files' to call 'ls-files'.

		:param args:
			is the list of arguments. If None is included, it will be pruned.
			This allows your commands to call git more conveniently as None
			is realized as non-existent

		:param kwargs:
			is a dict of keyword arguments.
			This function accepts the same optional keyword arguments
			as execute().

		``Examples``::
			git.rev_list('master', max_count=10, header=True)

		:return: Same as ``execute``"""
		# Handle optional arguments prior to calling transform_kwargs
		# otherwise these'll end up in args, which is bad.
		_kwargs = dict()
		for kwarg in execute_kwargs:
			try:
				_kwargs[kwarg] = kwargs.pop(kwarg)
			except KeyError:
				pass

		# Prepare the argument list
		opt_args = self.transform_kwargs(**kwargs)
		
		ext_args = self.__unpack_args([a for a in args if a is not None])
		args = opt_args + ext_args

		call = [self.GIT_PYTHON_GIT_EXECUTABLE, dashify(method)]
		call.extend(args)

		return self.execute(call, **_kwargs)
		
	def _parse_object_header(self, header_line):
		"""
		:param header_line:
			<hex_sha> type_string size_as_int
			
		:return: (hex_sha, type_string, size_as_int)
			
		:raise ValueError: if the header contains indication for an error due to 
			incorrect input sha"""
		tokens = header_line.split()
		if len(tokens) != 3:
			if not tokens:
				raise ValueError("SHA could not be resolved, git returned: %r" % (header_line.strip()))
			else:
				raise ValueError("SHA %s could not be resolved, git returned: %r" % (tokens[0], header_line.strip()))
			# END handle actual return value
		# END error handling
		
		if len(tokens[0]) != 40:
			raise ValueError("Failed to parse header: %r" % header_line) 
		return (tokens[0], tokens[1], int(tokens[2]))
	
	def __prepare_ref(self, ref):
		# required for command to separate refs on stdin
		refstr = str(ref)				# could be ref-object
		if refstr.endswith("\n"):
			return refstr
		return refstr + "\n"
	
	def __get_persistent_cmd(self, attr_name, cmd_name, *args,**kwargs):
		cur_val = getattr(self, attr_name)
		if cur_val is not None:
			return cur_val
			
		options = { "istream" : PIPE, "as_process" : True }
		options.update( kwargs )
		
		cmd = self._call_process( cmd_name, *args, **options )
		setattr(self, attr_name, cmd )
		return cmd
	
	def __get_object_header(self, cmd, ref):
		cmd.stdin.write(self.__prepare_ref(ref))
		cmd.stdin.flush()
		return self._parse_object_header(cmd.stdout.readline())
	
	def get_object_header(self, ref):
		""" Use this method to quickly examine the type and size of the object behind 
		the given ref. 
		
		:note: The method will only suffer from the costs of command invocation 
			once and reuses the command in subsequent calls. 
		
		:return: (hexsha, type_string, size_as_int)"""
		cmd = self.__get_persistent_cmd("cat_file_header", "cat_file", batch_check=True)
		return self.__get_object_header(cmd, ref)
		
	def get_object_data(self, ref):
		""" As get_object_header, but returns object data as well
		:return: (hexsha, type_string, size_as_int,data_string)
		:note: not threadsafe"""
		hexsha, typename, size, stream = self.stream_object_data(ref)
		data = stream.read(size)
		del(stream)
		return (hexsha, typename, size, data)
		
	def stream_object_data(self, ref):
		"""As get_object_header, but returns the data as a stream
		:return: (hexsha, type_string, size_as_int, stream)
		:note: This method is not threadsafe, you need one independent	Command instance
			per thread to be safe !"""
		cmd = self.__get_persistent_cmd("cat_file_all", "cat_file", batch=True)
		hexsha, typename, size = self.__get_object_header(cmd, ref)
		return (hexsha, typename, size, self.CatFileContentStream(size, cmd.stdout))
		
	def clear_cache(self):
		"""Clear all kinds of internal caches to release resources.
		
		Currently persistent commands will be interrupted.
		
		:return: self"""
		self.cat_file_all = None
		self.cat_file_header = None
		return self
