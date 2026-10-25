"""Path filters preserve Git's filename bytes at the native boundary."""

import contextlib
import os
from unittest.mock import patch

import pytest

from git import Git, _backend
from git.compat import safe_decode
from test.lib.fixtures import fixture_repo


@pytest.mark.skipif(os.name == "nt", reason="Windows CLI arguments cannot express arbitrary filename bytes")
@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_byte_pathspecs_preserve_matches(object_format):
    with fixture_repo("pathspec-bytes.sh", object_format) as repo:
        guard = (
            patch.object(Git, "execute", side_effect=AssertionError("unexpected pathspec CLI fallback"))
            if _backend.name == "gix"
            else contextlib.nullcontext()
        )
        with guard:
            # The tracked path is absent in the worktree, so only its matching filter is dirty.
            assert repo.is_dirty(path=safe_decode(b"tracked-\xff"))
            assert not repo.is_dirty(path=safe_decode(b"absent-\xff"))
            assert repo._get_untracked_files(safe_decode(b"[u\xff]*")) == ["untracked"]
            assert repo._get_untracked_files(safe_decode(b"absent-\xff")) == []
