# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: https://opensource.org/license/bsd-3-clause/
"""Specific test for pack streams only"""

from gitdb.test.performance.lib import (
    TestBigRepoR
)

from gitdb.db.pack import PackedDB
from gitdb.stream import NullStream
from gitdb.pack import PackEntity

import os
import sys
from time import time


class CountedNullStream(NullStream):
    __slots__ = '_bw'

    def __init__(self):
        self._bw = 0

    def bytes_written(self):
        return self._bw

    def write(self, d):
        self._bw += NullStream.write(self, d)


class TestPackStreamingPerformance(TestBigRepoR):

    def test_pack_writing(self):
        # see how fast we can write a pack from object streams.
        # This will not be fast, as we take time for decompressing the streams as well
        ostream = CountedNullStream()
        pdb = PackedDB(os.path.join(self.gitrepopath, "objects/pack"))

        ni = 1000
        count = 0
        st = time()
        for sha in pdb.sha_iter():
            count += 1
            pdb.stream(sha)
            if count == ni:
                break
        # END gather objects for pack-writing
        elapsed = time() - st
        print("PDB Streaming: Got %i streams by sha in in %f s ( %f streams/s )" %
              (ni, elapsed, ni / (elapsed or 1)), file=sys.stderr)

        st = time()
        PackEntity.write_pack((pdb.stream(sha) for sha in pdb.sha_iter()), ostream.write, object_count=ni)
        elapsed = time() - st
        total_kb = ostream.bytes_written() / 1000
        print(sys.stderr, "PDB Streaming: Wrote pack of size %i kb in %f s (%f kb/s)" %
              (total_kb, elapsed, total_kb / (elapsed or 1)), sys.stderr)

    def test_stream_reading(self):
        # raise SkipTest()
        pdb = PackedDB(os.path.join(self.gitrepopath, "objects/pack"))

        # streaming only, meant for --with-profile runs
        ni = 5000
        count = 0
        pdb_stream = pdb.stream
        total_size = 0
        st = time()
        for sha in pdb.sha_iter():
            if count == ni:
                break
            stream = pdb_stream(sha)
            stream.read()
            total_size += stream.size
            count += 1
        elapsed = time() - st
        total_kib = total_size / 1000
        print(sys.stderr, "PDB Streaming: Got %i streams by sha and read all bytes totallying %i KiB ( %f KiB / s ) in %f s ( %f streams/s )" %
              (ni, total_kib, total_kib / (elapsed or 1), elapsed, ni / (elapsed or 1)), sys.stderr)
