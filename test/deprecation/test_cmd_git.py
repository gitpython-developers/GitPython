# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Tests for dynamic and static characteristics of Git class and instance attributes.

Currently this all relates to the deprecated :attr:`Git.USE_SHELL` class attribute,
which can also be accessed through instances. Some tests directly verify its behavior,
including deprecation warnings, while others verify that other aspects of attribute
access are not inadvertently broken by mechanisms introduced to issue the warnings.

A note on multiprocessing
=========================

Because USE_SHELL has no instance state, this module does not include tests of pickling
and multiprocessing:

- Just as with a simple class attribute, when a class attribute with custom logic is set
  to another value, even before a worker process is created that uses the class, the
  worker process may see either the initial or new value, depending on the process start
  method. With "fork", changes are preserved. With "spawn" or "forkserver", re-importing
  the modules causes initial values to be set. Then the value in the parent at the time
  it dispatches the task is only set in the children if the parent has the task set it,
  or if it is set as a side effect of importing needed modules, or of unpickling objects
  passed to the child (for example, if it is set in a top-level statement of the module
  that defines the function submitted for the child worker process to call).

- When an attribute gains new logic provided by a property or custom descriptor, and the
  attribute involves instance-level state, incomplete or corrupted pickling can break
  multiprocessing. (For example, when an instance attribute is reimplemented using a
  descriptor that stores data in a global WeakKeyDictionary, pickled instances should be
  tested to ensure they are still working correctly.) But nothing like that applies
  here, because instance state is not involved. Although the situation is inherently
  complex as described above, it is independent of the attribute implementation.

- That USE_SHELL cannot be set on instances, and that when retrieved on instances it
  always gives the same value as on the class, is covered in the tests here.

A note on metaclass conflicts
=============================

The most important DeprecationWarning is for code like ``Git.USE_SHELL = True``, which
is a security risk. But this warning may not be possible to implement without a custom
metaclass. This is because a descriptor in a class can customize all forms of attribute
access on its instances, but can only customize getting an attribute on the class.
Retrieving a descriptor from a class calls its ``__get__`` method (if defined), but
replacing or deleting it does not call its ``__set__`` or ``__delete__`` methods.

Adding a metaclass is a potentially breaking change. This is because derived classes
that use an unrelated metaclass, whether directly or by inheriting from a class such as
abc.ABC that uses one, will raise TypeError when defined. These would have to be
modified to use a newly introduced metaclass that is a lower bound of both. Subclasses
remain unbroken in the far more typical case that they use no custom metaclass.

The tests in this module do not establish whether the danger of setting Git.USE_SHELL to
True is high enough, and applications of deriving from Git and using an unrelated custom
metaclass marginal enough, to justify introducing a metaclass to issue the warnings.
"""

import logging
import sys
from typing import Generator
import unittest.mock

if sys.version_info >= (3, 11):
    from typing import assert_type
else:
    from typing_extensions import assert_type

import pytest
from pytest import WarningsRecorder

from git.cmd import Git, GitMeta

from .lib import assert_no_deprecation_warning, suppress_deprecation_warning

_USE_SHELL_DEPRECATED_FRAGMENT = "Git.USE_SHELL is deprecated"
"""Text contained in all USE_SHELL deprecation warnings, and starting most of them."""

_USE_SHELL_DANGEROUS_FRAGMENT = "Setting Git.USE_SHELL to True is unsafe and insecure"
"""Beginning text of USE_SHELL deprecation warnings when USE_SHELL is set True."""

_logger = logging.getLogger(__name__)


@pytest.fixture
def restore_use_shell_state() -> Generator[None, None, None]:
    """Fixture to attempt to restore state associated with the USE_SHELL attribute.

    This is used to decrease the likelihood of state changes leaking out and affecting
    other tests. But the goal is not to assert implementation details of USE_SHELL.

    This covers two of the common implementation strategies, for convenience in testing
    both. USE_SHELL could be implemented in the metaclass:

    * With a separate _USE_SHELL backing attribute. If using a property or other
      descriptor, this is the natural way to do it, but custom __getattribute__ and
      __setattr__ logic, if it does more than adding warnings, may also use that.
    * Like a simple attribute, using USE_SHELL itself, stored as usual in the class
      dictionary, with custom __getattribute__/__setattr__ logic only to warn.

    This tries to save private state, tries to save the public attribute value, yields
    to the test case, tries to restore the public attribute value, then tries to restore
    private state. The idea is that if the getting or setting logic is wrong in the code
    under test, the state will still most likely be reset successfully.
    """
    no_value = object()

    # Try to save the original private state.
    try:
        old_private_value = Git._USE_SHELL  # type: ignore[attr-defined]
    except AttributeError:
        separate_backing_attribute = False
        try:
            old_private_value = type.__getattribute__(Git, "USE_SHELL")
        except AttributeError:
            old_private_value = no_value
            _logger.error("Cannot retrieve old private _USE_SHELL or USE_SHELL value")
    else:
        separate_backing_attribute = True

    try:
        # Try to save the original public value. Rather than attempt to restore a state
        # where the attribute is not set, if we cannot do this we allow AttributeError
        # to propagate out of the fixture, erroring the test case before its code runs.
        with suppress_deprecation_warning():
            old_public_value = Git.USE_SHELL

        # This doesn't have its own try-finally because pytest catches exceptions raised
        # during the yield. (The outer try-finally catches exceptions in this fixture.)
        yield

        # Try to restore the original public value.
        with suppress_deprecation_warning():
            Git.USE_SHELL = old_public_value
    finally:
        # Try to restore the original private state.
        if separate_backing_attribute:
            Git._USE_SHELL = old_private_value  # type: ignore[attr-defined]
        elif old_private_value is not no_value:
            type.__setattr__(Git, "USE_SHELL", old_private_value)


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


def test_get_use_shell_on_instance_default() -> None:
    """USE_SHELL can be read as an instance attribute, defaulting to False and warning.

    This is the same as test_get_use_shell_on_class_default above, but for instances.
    The test is repeated, instead of using parametrization, for clearer static analysis.
    """
    instance = Git()

    with pytest.deprecated_call() as ctx:
        use_shell = instance.USE_SHELL

    (message,) = [str(entry.message) for entry in ctx]  # Exactly one warning.
    assert message.startswith(_USE_SHELL_DEPRECATED_FRAGMENT)

    assert_type(use_shell, bool)

    # This comes after the static assertion, just in case it would affect the inference.
    assert not use_shell


def _assert_use_shell_full_results(
    set_value: bool,
    reset_value: bool,
    setting: WarningsRecorder,
    checking: WarningsRecorder,
    resetting: WarningsRecorder,
    rechecking: WarningsRecorder,
) -> None:
    # The attribute should take on the values set to it.
    assert set_value is True
    assert reset_value is False

    # Each access should warn exactly once.
    (set_message,) = [str(entry.message) for entry in setting]
    (check_message,) = [str(entry.message) for entry in checking]
    (reset_message,) = [str(entry.message) for entry in resetting]
    (recheck_message,) = [str(entry.message) for entry in rechecking]

    # Setting it to True should produce the special warning for that.
    assert _USE_SHELL_DEPRECATED_FRAGMENT in set_message
    assert set_message.startswith(_USE_SHELL_DANGEROUS_FRAGMENT)

    # All other operations should produce a usual warning.
    assert check_message.startswith(_USE_SHELL_DEPRECATED_FRAGMENT)
    assert reset_message.startswith(_USE_SHELL_DEPRECATED_FRAGMENT)
    assert recheck_message.startswith(_USE_SHELL_DEPRECATED_FRAGMENT)


def test_use_shell_set_and_get_on_class(restore_use_shell_state: None) -> None:
    """USE_SHELL can be set and re-read as a class attribute, always warning."""
    with pytest.deprecated_call() as setting:
        Git.USE_SHELL = True
    with pytest.deprecated_call() as checking:
        set_value = Git.USE_SHELL
    with pytest.deprecated_call() as resetting:
        Git.USE_SHELL = False
    with pytest.deprecated_call() as rechecking:
        reset_value = Git.USE_SHELL

    _assert_use_shell_full_results(
        set_value,
        reset_value,
        setting,
        checking,
        resetting,
        rechecking,
    )


def test_use_shell_set_on_class_get_on_instance(restore_use_shell_state: None) -> None:
    """USE_SHELL can be set on the class and read on an instance, always warning.

    This is like test_use_shell_set_and_get_on_class but it performs reads on an
    instance. There is some redundancy here in assertions about warnings when the
    attribute is set, but it is a separate test so that any bugs where a read on the
    class (or an instance) is needed first before a read on an instance (or the class)
    are detected.
    """
    instance = Git()

    with pytest.deprecated_call() as setting:
        Git.USE_SHELL = True
    with pytest.deprecated_call() as checking:
        set_value = instance.USE_SHELL
    with pytest.deprecated_call() as resetting:
        Git.USE_SHELL = False
    with pytest.deprecated_call() as rechecking:
        reset_value = instance.USE_SHELL

    _assert_use_shell_full_results(
        set_value,
        reset_value,
        setting,
        checking,
        resetting,
        rechecking,
    )


@pytest.mark.parametrize("value", [False, True])
def test_use_shell_cannot_set_on_instance(
    value: bool,
    restore_use_shell_state: None,  # In case of a bug where it does set USE_SHELL.
) -> None:
    instance = Git()
    with pytest.raises(AttributeError):
        instance.USE_SHELL = value  # type: ignore[misc]  # Name not in __slots__.


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize("original_value", [False, True])
def test_use_shell_is_mock_patchable_on_class_as_object_attribute(
    original_value: bool,
    restore_use_shell_state: None,
) -> None:
    """Asymmetric patching looking up USE_SHELL in ``__dict__`` doesn't corrupt state.

    Code using GitPython may temporarily set Git.USE_SHELL to a different value. Ideally
    it does not use unittest.mock.patch to do so, because that makes subtle assumptions
    about the relationship between attributes and dictionaries. If the attribute can be
    retrieved from the ``__dict__`` rather than directly, that value is assumed the
    correct one to restore, even by a normal setattr.

    The effect is that some ways of simulating a class attribute with added behavior can
    cause a descriptor, such as a property, to be set as the value of its own backing
    attribute during unpatching; then subsequent reads raise RecursionError. This
    happens if both (a) setting it on the class is customized in a metaclass and (b)
    getting it on instances is customized with a descriptor (such as a property) in the
    class itself.

    Although ideally code outside GitPython would not rely on being able to patch
    Git.USE_SHELL with unittest.mock.patch, the technique is widespread. Thus, USE_SHELL
    should be implemented in some way compatible with it. This test checks for that.
    """
    Git.USE_SHELL = original_value
    if Git.USE_SHELL is not original_value:
        raise RuntimeError("Can't set up the test")
    new_value = not original_value

    with unittest.mock.patch.object(Git, "USE_SHELL", new_value):
        assert Git.USE_SHELL is new_value

    assert Git.USE_SHELL is original_value


def test_execute_without_shell_arg_does_not_warn() -> None:
    """No deprecation warning is issued from operations implemented using Git.execute().

    When no ``shell`` argument is passed to Git.execute, which is when the value of
    USE_SHELL is to be used, the way Git.execute itself accesses USE_SHELL does not
    issue a deprecation warning.
    """
    with assert_no_deprecation_warning():
        Git().version()


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

    This is like test_class_dir, but for Git instances rather than the class itself.
    """
    instance = Git()
    actual = set(dir(instance))
    assert _EXPECTED_DIR_SUBSET <= actual


def test_metaclass_alias() -> None:
    """GitMeta aliases Git's metaclass, whether that is type or a custom metaclass."""

    def accept_metaclass_instance(cls: GitMeta) -> None:
        """Check that cls is statically recognizable as an instance of GitMeta."""

    accept_metaclass_instance(Git)  # assert_type would expect Type[Git], not GitMeta.

    # This comes after the static check, just in case it would affect the inference.
    assert type(Git) is GitMeta
