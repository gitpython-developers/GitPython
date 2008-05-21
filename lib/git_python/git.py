import os
import subprocess
import re
from utils import *
from method_missing import MethodMissingMixin

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

    def execute(self, command):
        """
        Handles executing the command on the shell and consumes and returns
        the returned information (stdout)

        ``command``
            The command to execute
        """
        print ' '.join(command)
        print self.git_dir
        proc = subprocess.Popen(command,
                                cwd = self.git_dir,
                                stdout=subprocess.PIPE
                                )
        proc.wait()
        stdout_value = proc.stdout.read()
        proc.stdout.close()
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
                    args.append("-%s" % k)
                    args.append(v)
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
            is a dict of keyword arguments

        Examples
            git.rev_list('master', max_count=10, header=True)

        Returns
            str
        """
        opt_args = self.transform_kwargs(**kwargs)
        ext_args = map(lambda a: (a == '--') and a or "%s" % a, args)
        args = opt_args + ext_args

        call = ['git-'+dashify(method)]
        call.extend(args)

        stdout_value = self.execute(call)
        return stdout_value
