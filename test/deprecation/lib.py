# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Support library for deprecation tests."""

__all__ = ["assert_no_deprecation_warning", "suppress_deprecation_warning"]

import contextlib
import warnings

from typing import Generator


@contextlib.contextmanager
def assert_no_deprecation_warning() -> Generator[None, None, None]:
    """Context manager to assert that code does not issue any deprecation warnings."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        warnings.simplefilter("error", PendingDeprecationWarning)
        yield


@contextlib.contextmanager
def suppress_deprecation_warning() -> Generator[None, None, None]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        yield
