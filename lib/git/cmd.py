# cmd.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os, sys
import subprocess
import re
from utils import *
from errors import GitCommandError

# Enables debugging of GitPython's git commands
GIT_PYTHON_TRACE = os.environ.get("GIT_PYTHON_TRACE", False)

execute_kwargs = ('istream', 'with_keep_cwd', 'with_extended_output',
                  'with_exceptions', 'with_raw_output')

extra = {}
if sys.platform == 'win32':
    extra = {'shell': True}

class Git(object):
    """
    The Git class manages communication with the Git binary.
    
	It provides a convenient interface to calling the Git binary, such as in::
	
	 g = Git( git_dir )
	 g.init()			        # calls 'git init' program
	 rval = g.ls_files()		# calls 'git ls-files' program
	
	``Debugging``
	    Set the GIT_PYTHON_TRACE environment variable print each invocation 
	    of the command to stdout.
	    Set its value to 'full' to see details about the returned values.
    """
    def __init__(self, git_dir=None):
        """
        Initialize this instance with:
        
        ``git_dir``
           Git directory we should work in. If None, we always work in the current 
           directory as returned by os.getcwd()
        """
        super(Git, self).__init__()
        self.git_dir = git_dir

    def __getattr__(self, name):
        """
        A convenience method as it allows to call the command as if it was 
        an object.
        Returns
            Callable object that will execute call _call_process with your arguments.
        """
        if name[:1] == '_':
            raise AttributeError(name)
        return lambda *args, **kwargs: self._call_process(name, *args, **kwargs)

    @property
    def get_dir(self):
        """
        Returns
            Git directory we are working on
        """
        return self.git_dir

    def execute(self, command,
                istream=None,
                with_keep_cwd=False,
                with_extended_output=False,
                with_exceptions=True,
                with_raw_output=False,
                ):
        """
        Handles executing the command on the shell and consumes and returns
        the returned information (stdout)

        ``command``
            The command argument list to execute.
            It should be a string, or a sequence of program arguments. The
            program to execute is the first item in the args sequence or string.

        ``istream``
            Standard input filehandle passed to subprocess.Popen.

        ``with_keep_cwd``
            Whether to use the current working directory from os.getcwd().
            GitPython uses get_work_tree() as its working directory by
            default and get_git_dir() for bare repositories.

        ``with_extended_output``
            Whether to return a (status, stdout, stderr) tuple.

        ``with_exceptions``
            Whether to raise an exception when git returns a non-zero status.

        ``with_raw_output``
            Whether to avoid stripping off trailing whitespace.

        Returns::
        
         str(output)                                  # extended_output = False (Default)
         tuple(int(status), str(stdout), str(stderr)) # extended_output = True
        
        Raise
        	GitCommandError
        
        NOTE
           If you add additional keyword arguments to the signature of this method, 
           you must update the execute_kwargs tuple housed in this module.
        """
        if GIT_PYTHON_TRACE and not GIT_PYTHON_TRACE == 'full':
            print ' '.join(command)

        # Allow the user to have the command executed in their working dir.
        if with_keep_cwd or self.git_dir is None:
          cwd = os.getcwd()
        else:
          cwd=self.git_dir

        # Start the process
        proc = subprocess.Popen(command,
                                cwd=cwd,
                                stdin=istream,
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                **extra
                                )

        # Wait for the process to return
        try:
            stdout_value = proc.stdout.read()
            stderr_value = proc.stderr.read()
            status = proc.wait()
        finally:
            proc.stdout.close()
            proc.stderr.close()

        # Strip off trailing whitespace by default
        if not with_raw_output:
            stdout_value = stdout_value.rstrip()
            stderr_value = stderr_value.rstrip()

        if with_exceptions and status != 0:
            raise GitCommandError(command, status, stderr_value)

        if GIT_PYTHON_TRACE == 'full':
            if stderr_value:
              print "%s -> %d: '%s' !! '%s'" % (command, status, stdout_value, stderr_value)
            elif stdout_value:
              print "%s -> %d: '%s'" % (command, status, stdout_value)
            else:
              print "%s -> %d" % (command, status)

        # Allow access to the command's status code
        if with_extended_output:
            return (status, stdout_value, stderr_value)
        else:
            return stdout_value

    def transform_kwargs(self, **kwargs):
        """
        Transforms Python style kwargs into git command line options.
        """
        args = []
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

    def _call_process(self, method, *args, **kwargs):
        """
        Run the given git command with the specified arguments and return
        the result as a String

        ``method``
            is the command. Contained "_" characters will be converted to dashes,
            such as in 'ls_files' to call 'ls-files'.

        ``args``
            is the list of arguments

        ``kwargs``
            is a dict of keyword arguments.
            This function accepts the same optional keyword arguments
            as execute().

        Examples::
            git.rev_list('master', max_count=10, header=True)

        Returns
            Same as execute()
        """

        # Handle optional arguments prior to calling transform_kwargs
        # otherwise these'll end up in args, which is bad.
        _kwargs = {}
        for kwarg in execute_kwargs:
            try:
                _kwargs[kwarg] = kwargs.pop(kwarg)
            except KeyError:
                pass

        # Prepare the argument list
        opt_args = self.transform_kwargs(**kwargs)
        ext_args = map(str, args)
        args = opt_args + ext_args

        call = ["git", dashify(method)]
        call.extend(args)

        return self.execute(call, **_kwargs)
