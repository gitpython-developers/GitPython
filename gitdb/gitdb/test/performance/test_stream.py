# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: https://opensource.org/license/bsd-3-clause/
"""Performance data streaming performance"""

from gitdb.test.performance.lib import TestBigRepoR
from gitdb.db import LooseObjectDB
from gitdb import IStream

from gitdb.util import bin_to_hex, remove
from gitdb.fun import chunk_size

from time import time
import os
import sys


from gitdb.test.lib import (
    make_memory_file,
    with_rw_directory,
)


#{ Utilities
def read_chunked_stream(stream):
    total = 0
    while True:
        chunk = stream.read(chunk_size)
        total += len(chunk)
        if len(chunk) < chunk_size:
            break
    # END read stream loop
    assert total == stream.size
    return stream


#} END utilities

class TestObjDBPerformance(TestBigRepoR):

    large_data_size_bytes = 1000 * 1000 * 50        # some MiB should do it
    moderate_data_size_bytes = 1000 * 1000 * 1      # just 1 MiB

    @with_rw_directory
    def test_large_data_streaming(self, path):
        ldb = LooseObjectDB(path)
        string_ios = list()         # list of streams we previously created

        # serial mode
        for randomize in range(2):
            desc = (randomize and 'random ') or ''
            print("Creating %s data ..." % desc, file=sys.stderr)
            st = time()
            size, stream = make_memory_file(self.large_data_size_bytes, randomize)
            elapsed = time() - st
            print("Done (in %f s)" % elapsed, file=sys.stderr)
            string_ios.append(stream)

            # writing - due to the compression it will seem faster than it is
            st = time()
            sha = ldb.store(IStream('blob', size, stream)).binsha
            elapsed_add = time() - st
            assert ldb.has_object(sha)
            db_file = ldb.readable_db_object_path(bin_to_hex(sha))
            fsize_kib = os.path.getsize(db_file) / 1000

            size_kib = size / 1000
            print("Added %i KiB (filesize = %i KiB) of %s data to loose odb in %f s ( %f Write KiB / s)" %
                  (size_kib, fsize_kib, desc, elapsed_add, size_kib / (elapsed_add or 1)), file=sys.stderr)

            # reading all at once
            st = time()
            ostream = ldb.stream(sha)
            shadata = ostream.read()
            elapsed_readall = time() - st

            stream.seek(0)
            assert shadata == stream.getvalue()
            print("Read %i KiB of %s data at once from loose odb in %f s ( %f Read KiB / s)" %
                  (size_kib, desc, elapsed_readall, size_kib / (elapsed_readall or 1)), file=sys.stderr)

            # reading in chunks of 1 MiB
            cs = 512 * 1000
            chunks = list()
            st = time()
            ostream = ldb.stream(sha)
            while True:
                data = ostream.read(cs)
                chunks.append(data)
                if len(data) < cs:
                    break
            # END read in chunks
            elapsed_readchunks = time() - st

            stream.seek(0)
            assert b''.join(chunks) == stream.getvalue()

            cs_kib = cs / 1000
            print("Read %i KiB of %s data in %i KiB chunks from loose odb in %f s ( %f Read KiB / s)" %
                  (size_kib, desc, cs_kib, elapsed_readchunks, size_kib / (elapsed_readchunks or 1)), file=sys.stderr)

            # del db file so we keep something to do
            ostream = None  # To release the file handle (win)
            remove(db_file)
        # END for each randomization factor
