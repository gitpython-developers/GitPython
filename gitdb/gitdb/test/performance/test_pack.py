# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: https://opensource.org/license/bsd-3-clause/
"""Performance tests for object store"""

from gitdb.test.performance.lib import (
    TestBigRepoR
)

from gitdb import (
    MemoryDB,
    GitDB,
    IStream,
)
from gitdb.typ import str_blob_type
from gitdb.exc import UnsupportedOperation
from gitdb.db.pack import PackedDB

import sys
import os
from time import time


class TestPackedDBPerformance(TestBigRepoR):

    def test_pack_random_access(self):
        pdb = PackedDB(os.path.join(self.gitrepopath, "objects/pack"))

        # sha lookup
        st = time()
        sha_list = list(pdb.sha_iter())
        elapsed = time() - st
        ns = len(sha_list)
        print("PDB: looked up %i shas by index in %f s ( %f shas/s )" % (ns, elapsed, ns / (elapsed or 1)), file=sys.stderr)

        # sha lookup: best-case and worst case access
        pdb_pack_info = pdb._pack_info
        # END shuffle shas
        st = time()
        for sha in sha_list:
            pdb_pack_info(sha)
        # END for each sha to look up
        elapsed = time() - st

        # discard cache
        del(pdb._entities)
        pdb.entities()
        print("PDB: looked up %i sha in %i packs in %f s ( %f shas/s )" %
              (ns, len(pdb.entities()), elapsed, ns / (elapsed or 1)), file=sys.stderr)
        # END for each random mode

        # query info and streams only
        max_items = 10000           # can wait longer when testing memory
        for pdb_fun in (pdb.info, pdb.stream):
            st = time()
            for sha in sha_list[:max_items]:
                pdb_fun(sha)
            elapsed = time() - st
            print("PDB: Obtained %i object %s by sha in %f s ( %f items/s )" %
                  (max_items, pdb_fun.__name__.upper(), elapsed, max_items / (elapsed or 1)), file=sys.stderr)
        # END for each function

        # retrieve stream and read all
        max_items = 5000
        pdb_stream = pdb.stream
        total_size = 0
        st = time()
        for sha in sha_list[:max_items]:
            stream = pdb_stream(sha)
            read_len = len(stream.read())
            assert read_len == stream.size
            total_size += stream.size
        elapsed = time() - st
        total_kib = total_size / 1000
        print("PDB: Obtained %i streams by sha and read all bytes totallying %i KiB ( %f KiB / s ) in %f s ( %f streams/s )" %
              (max_items, total_kib, total_kib / (elapsed or 1), elapsed, max_items / (elapsed or 1)), file=sys.stderr)

    def test_loose_correctness(self):
        """based on the pack(s) of our packed object DB, we will just copy and verify all objects in the back
        into the loose object db (memory).
        This should help finding dormant issues like this one https://github.com/gitpython-developers/GitPython/issues/220
        faster
        :note: It doesn't seem this test can find the issue unless the given pack contains highly compressed
        data files, like archives."""
        from gitdb.util import bin_to_hex
        pdb = GitDB(os.path.join(self.gitrepopath, 'objects'))
        mdb = MemoryDB()
        for c, sha in enumerate(pdb.sha_iter()):
            ostream = pdb.stream(sha)
            # the issue only showed on larger files which are hardly compressible ...
            if ostream.type != str_blob_type:
                continue
            istream = IStream(ostream.type, ostream.size, ostream.stream)
            mdb.store(istream)
            assert istream.binsha == sha, "Failed on object %s" % bin_to_hex(sha).decode('ascii')
            # this can fail ... sometimes, so the packs dataset should be huge
            assert len(mdb.stream(sha).read()) == ostream.size

            if c and c % 1000 == 0:
                print("Verified %i loose object compression/decompression cycles" % c, file=sys.stderr)
            mdb._cache.clear()
        # end for each sha to copy

    def test_correctness(self):
        pdb = PackedDB(os.path.join(self.gitrepopath, "objects/pack"))
        # disabled for now as it used to work perfectly, checking big repositories takes a long time
        print("Endurance run: verify streaming of objects (crc and sha)", file=sys.stderr)
        for crc in range(2):
            count = 0
            st = time()
            for entity in pdb.entities():
                pack_verify = entity.is_valid_stream
                sha_by_index = entity.index().sha
                for index in range(entity.index().size()):
                    try:
                        assert pack_verify(sha_by_index(index), use_crc=crc)
                        count += 1
                    except UnsupportedOperation:
                        pass
                    # END ignore old indices
                # END for each index
            # END for each entity
            elapsed = time() - st
            print("PDB: verified %i objects (crc=%i) in %f s ( %f objects/s )" %
                  (count, crc, elapsed, count / (elapsed or 1)), file=sys.stderr)
        # END for each verify mode
