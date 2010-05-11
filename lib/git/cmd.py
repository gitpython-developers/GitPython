# cmd.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os, sys
import subprocess
from utils import *
from errors import GitCommandError

# Enables debugging of GitPython's git commands
GIT_PYTHON_TRACE = os.environ.get("GIT_PYTHON_TRACE", False)

execute_kwargs = ('istream', 'with_keep_cwd', 'with_extended_output',
                  'with_exceptions', 'as_process', 
                  'output_stream' )

extra = {}
# NOTE: Execution through a shell on windows appears to be slightly faster, but in fact
# I consider it a problem whenever complex strings are passed and *interpreted* 
# by the shell beforehand. This can cause great confusion and reduces compatability
# between the OS which is why the shell should not be used ( unless it does not work
# otherwise )
#if sys.platform == 'win32':
#   extra = {'shell': False}

def dashify(string):
    return string.replace('_', '-')

class Git(object):
    """
    The Git class manages communication with the Git binary.
    
    It provides a convenient interface to calling the Git binary, such as in::
    
     g = Git( git_dir )
     g.init()                   # calls 'git init' program
     rval = g.ls_files()        # calls 'git ls-files' program
    
    ``Debugging``
        Set the GIT_PYTHON_TRACE environment variable print each invocation 
        of the command to stdout.
        Set its value to 'full' to see details about the returned values.
    """
    __slots__ = ("_working_dir", "cat_file_all", "cat_file_header")
    
    class AutoInterrupt(object):
        """
        Kill/Interrupt the stored process instance once this instance goes out of scope. It is 
        used to prevent processes piling up in case iterators stop reading.
        Besides all attributes are wired through to the contained process object.
        
        The wait method was overridden to perform automatic status code checking
        and possibly raise.
        """
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
                os.kill(self.proc.pid, 2)   # interrupt signal
            except AttributeError:
                # try windows 
                # for some reason, providing None for stdout/stderr still prints something. This is why 
                # we simply use the shell and redirect to nul. Its slower than CreateProcess, question 
                # is whether we really want to see all these messages. Its annoying no matter what.
                subprocess.call(("TASKKILL /F /T /PID %s 2>nul 1>nul" % str(self.proc.pid)), shell=True)
            # END exception handling 
            
        def __getattr__(self, attr):
            return getattr(self.proc, attr)
            
        def wait(self):
            """
            Wait for the process and return its status code. 
            
            Raise
                GitCommandError if the return status is not 0
            """
            status = self.proc.wait()
            if status != 0:
                raise GitCommandError(self.args, status, self.proc.stderr.read())
            # END status handling 
            return status
            
    
    
    def __init__(self, working_dir=None):
        """
        Initialize this instance with:
        
        ``working_dir``
           Git directory we should work in. If None, we always work in the current 
           directory as returned by os.getcwd().
           It is meant to be the working tree directory if available, or the 
           .git directory in case of bare repositories.
        """
        super(Git, self).__init__()
        self._working_dir = working_dir
        
        # cached command slots
        self.cat_file_header = None
        self.cat_file_all = None

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
    def working_dir(self):
        """
        Returns
            Git directory we are working on
        """
        return self._working_dir

    def execute(self, command,
                istream=None,
                with_keep_cwd=False,
                with_extended_output=False,
                with_exceptions=True,
                as_process=False, 
                output_stream=None
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
            The cmd otherwise uses its own working_dir that it has been initialized
            with if possible.

        ``with_extended_output``
            Whether to return a (status, stdout, stderr) tuple.

        ``with_exceptions``
            Whether to raise an exception when git returns a non-zero status.

        ``as_process``
            Whether to return the created process instance directly from which 
            streams can be read on demand. This will render with_extended_output and 
            with_exceptions ineffective - the caller will have 
            to deal with the details himself.
            It is important to note that the process will be placed into an AutoInterrupt
            wrapper that will interrupt the process once it goes out of scope. If you 
            use the command in iterators, you should pass the whole process instance 
            instead of a single stream.
            
        ``output_stream``
            If set to a file-like object, data produced by the git command will be 
            output to the given stream directly.
            This feature only has any effect if as_process is False. Processes will
            always be created with a pipe due to issues with subprocess.
            This merely is a workaround as data will be copied from the 
            output pipe to the given output stream directly.
            
        
        Returns::
        
         str(output)                                   # extended_output = False (Default)
         tuple(int(status), str(stdout), str(stderr)) # extended_output = True
         
         if ouput_stream is True, the stdout value will be your output stream:
         output_stream                                  # extended_output = False
         tuple(int(status), output_stream, str(stderr))# extended_output = True
        
        Raise
            GitCommandError
        
        NOTE
           If you add additional keyword arguments to the signature of this method, 
           you must update the execute_kwargs tuple housed in this module.
        """
        if GIT_PYTHON_TRACE and not GIT_PYTHON_TRACE == 'full':
            print ' '.join(command)

        # Allow the user to have the command executed in their working dir.
        if with_keep_cwd or self._working_dir is None:
          cwd = os.getcwd()
        else:
          cwd=self._working_dir
          
        # Start the process
        proc = subprocess.Popen(command,
                                cwd=cwd,
                                stdin=istream,
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                **extra
                                )
        if as_process:
            return self.AutoInterrupt(proc, command)
        
        # Wait for the process to return
        status = 0
        stdout_value = ''
        stderr_value = ''
        try:
            if output_stream is None:
                stdout_value = proc.stdout.read().rstrip()      # strip trailing "\n"
            else:
                max_chunk_size = 1024*64
                while True:
                    chunk = proc.stdout.read(max_chunk_size)
                    output_stream.write(chunk)
                    if len(chunk) < max_chunk_size:
                        break
                # END reading output stream
                stdout_value = output_stream
            # END stdout handling
            stderr_value = proc.stderr.read().rstrip()          # strip trailing "\n"
            
            # waiting here should do nothing as we have finished stream reading
            status = proc.wait()
        finally:
            proc.stdout.close()
            proc.stderr.close()

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
        """
        Run the given git command with the specified arguments and return
        the result as a String

        ``method``
            is the command. Contained "_" characters will be converted to dashes,
            such as in 'ls_files' to call 'ls-files'.

        ``args``
            is the list of arguments. If None is included, it will be pruned.
            This allows your commands to call git more conveniently as None
            is realized as non-existent

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
        
        ext_args = self.__unpack_args([a for a in args if a is not None])
        args = opt_args + ext_args

        call = ["git", dashify(method)]
        call.extend(args)

        return self.execute(call, **_kwargs)
        
    def _parse_object_header(self, header_line):
        """
        ``header_line``
            <hex_sha> type_string size_as_int
            
        Returns
            (hex_sha, type_string, size_as_int)
            
        Raises
            ValueError if the header contains indication for an error due to incorrect 
            input sha
        """
        tokens = header_line.split()
        if len(tokens) != 3:
            raise ValueError("SHA named %s could not be resolved, git returned: %r" % (tokens[0], header_line.strip()) )
        if len(tokens[0]) != 40:
            raise ValueError("Failed to parse header: %r" % header_line) 
        return (tokens[0], tokens[1], int(tokens[2]))
    
    def __prepare_ref(self, ref):
        # required for command to separate refs on stdin
        refstr = str(ref)               # could be ref-object
        if refstr.endswith("\n"):
            return refstr
        return refstr + "\n"
    
    def __get_persistent_cmd(self, attr_name, cmd_name, *args,**kwargs):
        cur_val = getattr(self, attr_name)
        if cur_val is not None:
            return cur_val
            
        options = { "istream" : subprocess.PIPE, "as_process" : True }
        options.update( kwargs )
        
        cmd = self._call_process( cmd_name, *args, **options )
        setattr(self, attr_name, cmd )
        return cmd
    
    def __get_object_header(self, cmd, ref):
        cmd.stdin.write(self.__prepare_ref(ref))
        cmd.stdin.flush()
        return self._parse_object_header(cmd.stdout.readline())
    
    def get_object_header(self, ref):
        """
        Use this method to quickly examine the type and size of the object behind 
        the given ref. 
        
        NOTE
            The method will only suffer from the costs of command invocation 
            once and reuses the command in subsequent calls. 
        
        Return:
            (hexsha, type_string, size_as_int)
        """
        cmd = self.__get_persistent_cmd("cat_file_header", "cat_file", batch_check=True)
        return self.__get_object_header(cmd, ref)
        
    def get_object_data(self, ref):
        """
        As get_object_header, but returns object data as well
        
        Return:
            (hexsha, type_string, size_as_int,data_string)
        """
        cmd = self.__get_persistent_cmd("cat_file_all", "cat_file", batch=True)
        hexsha, typename, size = self.__get_object_header(cmd, ref)
        data = cmd.stdout.read(size)
        cmd.stdout.read(1)      # finishing newlines
        
        return (hexsha, typename, size, data)
        
    def clear_cache(self):
        """
        Clear all kinds of internal caches to release resources.
        
        Currently persistent commands will be interrupted.
        
        Returns
            self
        """
        self.cat_file_all = None
        self.cat_file_header = None
        return self
