"""Tests for dynamic and static attribute errors."""

import pytest

import git


def test_no_attribute() -> None:
    with pytest.raises(AttributeError):
        git.foo
