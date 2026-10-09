# This module is part of GitPython and is released under the 3-Clause BSD License.
"""Validation shared by the Git tree output adapters."""

from typing import Union

from git.util import _validate_repo_path

__all__ = []


def _validate_tree_entry_name(name: str, mode: Union[int, None] = None) -> None:
    if "/" in name:
        raise ValueError("Tree entry names must not contain '/' characters")
    # A tree name is a component, not a rooted path; a colon cannot select a drive.
    _validate_repo_path("tree/" + name, mode)
