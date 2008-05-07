import os
import subprocess
import re
from utils import *
from method_missing import MethodMissingMixin

class Git(MethodMissingMixin):
    def __init__(self, git_dir):
        super(Git, self).__init__()
        self.git_dir = git_dir
    
    git_binary = "/usr/bin/env git"
    
    @property
    def get_dir(self):
        return self.git_dir
        
    def execute(self, command):
        print command
        proc = subprocess.Popen(command, 
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT
                                )
        stdout_value = proc.communicate()[0]
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
                    args.append("-%s %r" % (k, v))
            else:
                if v is True:
                    args.append("--%s" % dashify(k))
                else:
                    args.append("--%s=%r" % (dashify(k), v))
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
        ext_args = map(lambda a: (a == '--') and a or "%s" % shell_escape(a), args)
        args = opt_args + ext_args
        
        call = "%s --git-dir=%s %s %s" % (self.git_binary, self.git_dir, dashify(method), ' '.join(args))
        stdout_value = self.execute(call)
        return stdout_value
