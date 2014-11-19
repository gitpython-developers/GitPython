"""Module containing index utilities"""
import struct
import tempfile
import os

__all__ = ('TemporaryFileSwap', 'post_clear_cache', 'default_index', 'git_working_dir')

#{ Aliases
pack = struct.pack
unpack = struct.unpack


#} END aliases

class TemporaryFileSwap(object):

    """Utility class moving a file to a temporary location within the same directory
    and moving it back on to where on object deletion."""
    __slots__ = ("file_path", "tmp_file_path")

    def __init__(self, file_path):
        self.file_path = file_path
        self.tmp_file_path = self.file_path + tempfile.mktemp('', '', '')
        # it may be that the source does not exist
        try:
            os.rename(self.file_path, self.tmp_file_path)
        except OSError:
            pass

    def __del__(self):
        if os.path.isfile(self.tmp_file_path):
            if os.name == 'nt' and os.path.exists(self.file_path):
                os.remove(self.file_path)
            os.rename(self.tmp_file_path, self.file_path)
        # END temp file exists


#{ Decorators

def post_clear_cache(func):
    """Decorator for functions that alter the index using the git command. This would
    invalidate our possibly existing entries dictionary which is why it must be
    deleted to allow it to be lazily reread later.

    :note:
        This decorator will not be required once all functions are implemented
        natively which in fact is possible, but probably not feasible performance wise.
    """

    def post_clear_cache_if_not_raised(self, *args, **kwargs):
        rval = func(self, *args, **kwargs)
        self._delete_entries_cache()
        return rval

    # END wrapper method
    post_clear_cache_if_not_raised.__name__ = func.__name__
    return post_clear_cache_if_not_raised


def default_index(func):
    """Decorator assuring the wrapped method may only run if we are the default
    repository index. This is as we rely on git commands that operate
    on that index only. """

    def check_default_index(self, *args, **kwargs):
        if self._file_path != self._index_path():
            raise AssertionError(
                "Cannot call %r on indices that do not represent the default git index" % func.__name__)
        return func(self, *args, **kwargs)
    # END wrpaper method

    check_default_index.__name__ = func.__name__
    return check_default_index


def git_working_dir(func):
    """Decorator which changes the current working dir to the one of the git
    repository in order to assure relative paths are handled correctly"""

    def set_git_working_dir(self, *args, **kwargs):
        cur_wd = os.getcwd()
        os.chdir(self.repo.working_tree_dir)
        try:
            return func(self, *args, **kwargs)
        finally:
            os.chdir(cur_wd)
        # END handle working dir
    # END wrapper

    set_git_working_dir.__name__ = func.__name__
    return set_git_working_dir

#} END decorators
