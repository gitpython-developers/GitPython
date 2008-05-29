import os
import subprocess
import re
from utils import *
from method_missing import MethodMissingMixin

# Enables debugging of GitPython's git commands
GIT_PYTHON_TRACE = os.environ.get("GIT_PYTHON_TRACE", False)

class Git(MethodMissingMixin):
    """
    The Git class manages communication with the Git binary
    """
    def __init__(self, git_dir):
        super(Git, self).__init__()
        self.git_dir = git_dir

    @property
    def get_dir(self):
        return self.git_dir

    def execute(self, command,
                istream = None,
                with_status = False,
                ):
        """
        Handles executing the command on the shell and consumes and returns
        the returned information (stdout)

        ``command``
            The command argument list to execute

        ``istream``
            Standard input filehandle passed to subprocess.Popen.

        ``with_status``
            Whether to return a (status, str) tuple.

        Returns
            str(output)                     # with_status = False (Default)
            tuple(int(status), str(output)) # with_status = True
        """

        if GIT_PYTHON_TRACE:
            print command

        # Start the process
        proc = subprocess.Popen(command,
                                cwd = self.git_dir,
                                stdin = istream,
                                stdout = subprocess.PIPE
                                )

        # Wait for the process to return
        stdout_value, err = proc.communicate()
        proc.stdout.close()
        # Grab the exit status
        status = proc.poll()
        # Allow access to the command's status code
        if with_status:
            return (status, stdout_value)
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
                else:
                    args.append("-%s%s" % (k, v))
            else:
                if v is True:
                    args.append("--%s" % dashify(k))
                else:
                    args.append("--%s=%s" % (dashify(k), v))
        return args

    def method_missing(self, method, *args, **kwargs):
        """
        Run the given git command with the specified arguments and return
        the result as a String

        ``method``
            is the command

        ``args``
            is the list of arguments

        ``kwargs``
            is a dict of keyword arguments.
            This function accepts the same optional keyword arguments
            as execute().

        Examples
            git.rev_list('master', max_count=10, header=True)

        Returns
            Same as execute()
        """

        # Handle optional arguments prior to calling transform_kwargs
        # otherwise these'll end up in args, which is bad.
        istream = pop_key(kwargs, "istream")
        with_status = pop_key(kwargs, "with_status")
        # Prepare the argument list
        opt_args = self.transform_kwargs(**kwargs)
        ext_args = map(str, args)
        args = opt_args + ext_args

        call = ["git", dashify(method)]
        call.extend(args)

        return self.execute(call,
                            istream = istream,
                            with_status = with_status,
                            )
