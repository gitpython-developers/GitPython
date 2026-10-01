# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Tests for the blob filter."""

from pathlib import Path
from typing import Sequence, Tuple

import pytest

from git.index.typ import BlobFilter, StageType
from git.objects import Blob
from git.types import PathLike


@pytest.mark.parametrize(
    "paths, path, expected_result",
    [
        ((Path("foo"),), Path("foo"), True),
        ((Path("foo"),), Path("foo/bar"), True),
        ((Path("foo/bar"),), Path("foo"), False),
        ((Path("foo"), Path("bar")), Path("foo"), True),
    ],
)
def test_blob_filter(paths: Sequence[PathLike], path: PathLike, expected_result: bool) -> None:
    """Test the blob filter."""
    blob_filter = BlobFilter(paths)

    binsha = b"a" * 20
    stage_type: StageType = 0
    blob: Blob = Blob(repo=None, binsha=binsha, path=path)  # type: ignore[arg-type]
    stage_blob: Tuple[StageType, Blob] = (stage_type, blob)

    result = blob_filter(stage_blob)

    assert result == expected_result
