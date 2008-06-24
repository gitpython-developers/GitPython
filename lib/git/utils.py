import os

def dashify(string):
    return string.replace('_', '-')

def touch(filename):
    os.utime(filename)

def is_git_dir(d):
    """ This is taken from the git setup.c:is_git_directory
        function."""

    if os.path.isdir(d) and \
            os.path.isdir(os.path.join(d, 'objects')) and \
            os.path.isdir(os.path.join(d, 'refs')):
        headref = os.path.join(d, 'HEAD')
        return os.path.isfile(headref) or \
                (os.path.islink(headref) and
                os.readlink(headref).startswith('refs'))
    return False
