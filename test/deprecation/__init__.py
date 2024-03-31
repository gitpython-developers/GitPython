# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

"""Tests of deprecation warnings and possible related attribute bugs.

Most deprecation warnings are "basic" in the sense that there is no special complexity
to consider, in introducing them. However, to issue deprecation warnings on mere
attribute access can involve adding new dynamic behavior. This can lead to subtle bugs
or less useful dynamic metadata. It can also weaken static typing, as happens if a type
checker sees a method like ``__getattr__`` in a module or class whose attributes it did
not already judge to be dynamic. This test.deprecation submodule covers all three cases:
the basic cases, subtle dynamic behavior, and subtle static type checking issues.

Static type checking is "tested" by a combination of code that should not be treated as
a type error but would be in the presence of particular bugs, and code that *should* be
treated as a type error and is accordingly marked ``# type: ignore[REASON]`` (for
specific ``REASON``. The latter will only produce mypy errors when the expectation is
not met if it is configured with ``warn_unused_ignores = true``.
"""
