"""Package with general repository related functions"""
import os
from git.util import is_git_dir

__all__ = ('is_git_dir', 'touch')

def touch(filename):
	fp = open(filename, "a")
	fp.close()

