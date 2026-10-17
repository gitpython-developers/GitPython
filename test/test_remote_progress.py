# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Tests for static characteristics of remote progress helpers."""

from typing import AnyStr

from git import RemoteProgress


def test_parse_progress_line_override_can_return_non_none() -> None:
    """Subclass overrides may return a value without violating base typing."""

    class ReturningProgress(RemoteProgress):
        def _parse_progress_line(self, line: AnyStr) -> str:
            super()._parse_progress_line(line)
            return "handled"

    assert ReturningProgress()._parse_progress_line("unmatched progress") == "handled"
