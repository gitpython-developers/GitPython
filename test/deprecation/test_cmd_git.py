"""Tests for static and dynamic characteristics of Git class and instance attributes.

Currently this all relates to the deprecated :class:`Git.USE_SHELL` class attribute,
which can also be accessed through instances. Some tests directly verify its behavior,
including deprecation warnings, while others verify that other aspects of attribute
access are not inadvertently broken by mechanisms introduced to issue the warnings.
"""

import contextlib
import sys
from typing import Generator

if sys.version_info >= (3, 11):
    from typing import assert_type
else:
    from typing_extensions import assert_type

import pytest

from git.cmd import Git

_USE_SHELL_DEPRECATED_FRAGMENT = "Git.USE_SHELL is deprecated"
"""Text contained in all USE_SHELL deprecation warnings, and starting most of them."""

_USE_SHELL_DANGEROUS_FRAGMENT = "Setting Git.USE_SHELL to True is unsafe and insecure"
"""Beginning text of USE_SHELL deprecation warnings when USE_SHELL is set True."""


@pytest.fixture
def reset_backing_attribute() -> Generator[None, None, None]:
    """Fixture to reset the private ``_USE_SHELL`` attribute.

    This is used to decrease the likelihood of state changes leaking out and affecting
    other tests. But the goal is not to assert that ``_USE_SHELL`` is used, nor anything
    about how or when it is used, which is an implementation detail subject to change.

    This is possible but inelegant to do with pytest's monkeypatch fixture, which only
    restores attributes that it has previously been used to change, create, or remove.
    """
    no_value = object()
    try:
        old_value = Git._USE_SHELL
    except AttributeError:
        old_value = no_value

    yield

    if old_value is no_value:
        with contextlib.suppress(AttributeError):
            del Git._USE_SHELL
    else:
        Git._USE_SHELL = old_value


def test_cannot_access_undefined_on_git_class() -> None:
    """Accessing a bogus attribute on the Git class remains a dynamic and static error.

    This differs from Git instances, where most attribute names will dynamically
    synthesize a "bound method" that runs a git subcommand when called.
    """
    with pytest.raises(AttributeError):
        Git.foo  # type: ignore[attr-defined]


def test_get_use_shell_on_class_default() -> None:
    """USE_SHELL can be read as a class attribute, defaulting to False and warning."""
    with pytest.deprecated_call() as ctx:
        use_shell = Git.USE_SHELL

    (message,) = [str(entry.message) for entry in ctx]  # Exactly one warning.
    assert message.startswith(_USE_SHELL_DEPRECATED_FRAGMENT)

    assert_type(use_shell, bool)

    # This comes after the static assertion, just in case it would affect the inference.
    assert not use_shell


# FIXME: More robustly check that each operation really issues exactly one deprecation
# warning, even if this requires relying more on reset_backing_attribute doing its job.
def test_use_shell_on_class(reset_backing_attribute) -> None:
    """USE_SHELL can be written and re-read as a class attribute, always warning."""
    # We assert in a "safe" order, using reset_backing_attribute only as a backstop.
    with pytest.deprecated_call() as ctx:
        Git.USE_SHELL = True
        set_value = Git.USE_SHELL
        Git.USE_SHELL = False
        reset_value = Git.USE_SHELL

    # The attribute should take on the values set to it.
    assert set_value is True
    assert reset_value is False

    messages = [str(entry.message) for entry in ctx]
    set_message, check_message, reset_message, recheck_message = messages

    # Setting it to True should produce the special warning for that.
    assert _USE_SHELL_DEPRECATED_FRAGMENT in set_message
    assert set_message.startswith(_USE_SHELL_DANGEROUS_FRAGMENT)

    # All other operations should produce a usual warning.
    assert check_message.startswith(_USE_SHELL_DEPRECATED_FRAGMENT)
    assert reset_message.startswith(_USE_SHELL_DEPRECATED_FRAGMENT)
    assert recheck_message.startswith(_USE_SHELL_DEPRECATED_FRAGMENT)


# FIXME: Test behavior on instances (where we can get but not set).

# FIXME: Test behavior with multiprocessing (the attribute needs to pickle properly).


_EXPECTED_DIR_SUBSET = {
    "cat_file_all",
    "cat_file_header",
    "GIT_PYTHON_TRACE",
    "USE_SHELL",  # The attribute we get deprecation warnings for.
    "GIT_PYTHON_GIT_EXECUTABLE",
    "refresh",
    "is_cygwin",
    "polish_url",
    "check_unsafe_protocols",
    "check_unsafe_options",
    "AutoInterrupt",
    "CatFileContentStream",
    "__init__",
    "__getattr__",
    "set_persistent_git_options",
    "working_dir",
    "version_info",
    "execute",
    "environment",
    "update_environment",
    "custom_environment",
    "transform_kwarg",
    "transform_kwargs",
    "__call__",
    "_call_process",  # Not currently considered public, but unlikely to change.
    "get_object_header",
    "get_object_data",
    "stream_object_data",
    "clear_cache",
}
"""Some stable attributes dir() should include on the Git class and its instances.

This is intentionally incomplete, but includes substantial variety. Most importantly, it
includes both ``USE_SHELL`` and a wide sampling of other attributes.
"""


def test_class_dir() -> None:
    """dir() on the Git class includes its statically known attributes.

    This tests that the mechanism that adds dynamic behavior to USE_SHELL accesses so
    that all accesses issue warnings does not break dir() for the class, neither for
    USE_SHELL nor for ordinary (non-deprecated) attributes.
    """
    actual = set(dir(Git))
    assert _EXPECTED_DIR_SUBSET <= actual


def test_instance_dir() -> None:
    """dir() on Git objects includes its statically known attributes.

    This is like test_class_dir, but for Git instance rather than the class itself.
    """
    instance = Git()
    actual = set(dir(instance))
    assert _EXPECTED_DIR_SUBSET <= actual
