# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: https://opensource.org/license/bsd-3-clause/
"""Utilities used in ODB testing"""
from gitdb import OStream

import sys
import random
from array import array

from io import BytesIO

import glob
import unittest
import tempfile
import shutil
import os
import gc
import subprocess
from functools import wraps


#{ Bases

class TestBase(unittest.TestCase):
    """Base class for all tests

    TestCase providing access to readonly repositories using the following member variables.

    * gitrepopath

     * base path of a generated repository containing packed and loose objects
    """

    @classmethod
    def setUpClass(cls):
        try:
            super().setUpClass()
        except AttributeError:
            pass

        temporary = tempfile.TemporaryDirectory(prefix="gitdb-fixture-")
        cls.addClassCleanup(temporary.cleanup)
        env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        env.update(
            GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
            GIT_AUTHOR_NAME='GitDB Tests', GIT_AUTHOR_EMAIL='tests@example.invalid',
            GIT_COMMITTER_NAME='GitDB Tests', GIT_COMMITTER_EMAIL='tests@example.invalid',
            GIT_AUTHOR_DATE='2001-01-01T00:00:00 +0000', GIT_COMMITTER_DATE='2001-01-01T00:00:00 +0000',
        )
        # Keep the standalone suite usable on Python 3.8 without GixPython.
        subprocess.run(['bash', fixture_path('repository.sh')], cwd=temporary.name, env=env, check=True)
        cls.gitrepopath = os.path.join(temporary.name, 'repo', '.git')


#} END bases

#{ Decorators

def with_rw_directory(func):
    """Create a temporary directory which can be written to, remove it if the
    test succeeds, but leave it otherwise to aid additional debugging"""

    def wrapper(self):
        path = tempfile.mktemp(prefix=func.__name__)
        os.mkdir(path)
        keep = False
        try:
            try:
                return func(self, path)
            except Exception:
                sys.stderr.write(f"Test {type(self).__name__}.{func.__name__} failed, output is at {path!r}\n")
                keep = True
                raise
        finally:
            # Need to collect here to be sure all handles have been closed. It appears
            # a windows-only issue. In fact things should be deleted, as well as
            # memory maps closed, once objects go out of scope. For some reason
            # though this is not the case here unless we collect explicitly.
            if not keep:
                gc.collect()
                shutil.rmtree(path)
        # END handle exception
    # END wrapper

    wrapper.__name__ = func.__name__
    return wrapper


def with_packs_rw(func):
    """Function that provides a path into which the packs for testing should be
    copied. Will pass on the path to the actual function afterwards"""

    def wrapper(self, path):
        src_pack_glob = fixture_path('packs/*')
        copy_files_globbed(src_pack_glob, path, hard_link_ok=True)
        return func(self, path)
    # END wrapper

    wrapper.__name__ = func.__name__
    return wrapper

#} END decorators

#{ Routines


def fixture_path(relapath=''):
    """:return: absolute path into the fixture directory
    :param relapath: relative path into the fixtures directory, or ''
        to obtain the fixture directory itself"""
    return os.path.join(os.path.dirname(__file__), 'fixtures', relapath)


def copy_files_globbed(source_glob, target_dir, hard_link_ok=False):
    """Copy all files found according to the given source glob into the target directory
    :param hard_link_ok: if True, hard links will be created if possible. Otherwise
        the files will be copied"""
    for src_file in glob.glob(source_glob):
        if hard_link_ok and hasattr(os, 'link'):
            target = os.path.join(target_dir, os.path.basename(src_file))
            try:
                os.link(src_file, target)
            except OSError:
                shutil.copy(src_file, target_dir)
            # END handle cross device links ( and resulting failure )
        else:
            shutil.copy(src_file, target_dir)
        # END try hard link
    # END for each file to copy


def make_bytes(size_in_bytes, randomize=False):
    """:return: string with given size in bytes
    :param randomize: try to produce a very random stream"""
    actual_size = size_in_bytes // 4
    producer = range(actual_size)
    if randomize:
        producer = list(producer)
        random.shuffle(producer)
    # END randomize
    a = array('i', producer)
    return a.tobytes()


def make_object(type, data):
    """:return: bytes resembling an uncompressed object"""
    odata = "blob %i\0" % len(data)
    return odata.encode("ascii") + data


def make_memory_file(size_in_bytes, randomize=False):
    """:return: tuple(size_of_stream, stream)
    :param randomize: try to produce a very random stream"""
    d = make_bytes(size_in_bytes, randomize)
    return len(d), BytesIO(d)

#} END routines

#{ Stream Utilities


class DummyStream:

    def __init__(self):
        self.was_read = False
        self.bytes = 0
        self.closed = False

    def read(self, size):
        self.was_read = True
        self.bytes = size

    def close(self):
        self.closed = True

    def _assert(self):
        assert self.was_read


class DeriveTest(OStream):

    def __init__(self, sha, type, size, stream, *args, **kwargs):
        self.myarg = kwargs.pop('myarg')
        self.args = args

    def _assert(self):
        assert self.args
        assert self.myarg

#} END stream utilitiess
