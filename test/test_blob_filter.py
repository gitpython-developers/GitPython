"""Test the blob filter."""
from pathlib import Path
from typing import Sequence, Tuple
from unittest.mock import MagicMock

import pytest

from git.index.typ import BlobFilter, StageType
from git.objects import Blob
from git.types import PathLike


# fmt: off
@pytest.mark.parametrize('paths, path, expected_result', [
    ((Path("foo"),), Path("foo"), True),
    ((Path("foo"),), Path("foo/bar"), True),
    ((Path("foo/bar"),), Path("foo"), False),
    ((Path("foo"), Path("bar")), Path("foo"), True),
])
# fmt: on
def test_blob_filter(paths: Sequence[PathLike], path: PathLike, expected_result: bool) -> None:
    """Test the blob filter."""
    blob_filter = BlobFilter(paths)

    binsha = MagicMock(__len__=lambda self: 20)
    stage_type: StageType = 0
    blob: Blob = Blob(repo=MagicMock(), binsha=binsha, path=path)
    stage_blob: Tuple[StageType, Blob] = (stage_type, blob)

    result = blob_filter(stage_blob)

    assert result == expected_result
