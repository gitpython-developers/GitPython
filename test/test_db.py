# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

from io import BytesIO
import os.path as osp
from unittest import mock

from gitdb import IStream
from gitdb.db import LooseObjectDB
from gitdb.typ import str_blob_type

from git.db import GitCmdObjectDB
from git.exc import BadObject
from git.util import bin_to_hex

from test.lib import TestBase, with_rw_repo


class TestDB(TestBase):
    @with_rw_repo("HEAD")
    def test_store_uses_hash_object(self, rw_repo):
        data = b"hello world"
        with mock.patch.object(LooseObjectDB, "store", side_effect=AssertionError("unexpected loose-object write")):
            istream = rw_repo.odb.store(IStream(str_blob_type, len(data), BytesIO(data)))

        assert rw_repo.odb.stream(istream.binsha).read() == data

    def test_base(self):
        gdb = GitCmdObjectDB(osp.join(self.rorepo.git_dir, "objects"), self.rorepo.git)

        # Partial to complete - works with everything.
        hexsha = bin_to_hex(gdb.partial_to_complete_sha_hex("0.1.6"))
        assert len(hexsha) == 40

        assert bin_to_hex(gdb.partial_to_complete_sha_hex(hexsha[:20])) == hexsha

        # Fails with BadObject.
        for invalid_rev in ("0000", "bad/ref", "super bad"):
            self.assertRaises(BadObject, gdb.partial_to_complete_sha_hex, invalid_rev)
