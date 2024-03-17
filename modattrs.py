#!/usr/bin/env python

"""Script to get the names and "stabilized" reprs of module attributes in GitPython.

Run with :envvar:`PYTHONHASHSEED` set to ``0`` for fully comparable results. These are
only still meaningful for comparing if the same platform and Python version are used.

The output of this script should probably not be committed, because within the reprs of
objects found in modules, it may contain sensitive information, such as API keys stored
in environment variables. The "sanitization" performed here is only for common forms of
whitespace that clash with the output format.
"""

# fmt: off

__all__ = ["git", "main"]

import itertools
import re
import sys

import git


def main():
    # This assumes `import git` causes all of them to be loaded.
    gitpython_modules = sorted(
        (module_name, module)
        for module_name, module in sys.modules.items()
        if re.match(r"git(?:\.|$)", module_name)
    )

    # We will print two blank lines between successive module reports.
    separators = itertools.chain(("",), itertools.repeat("\n\n"))

    # Report each module's contents.
    for (module_name, module), separator in zip(gitpython_modules, separators):
        print(f"{separator}{module_name}:")

        attributes = sorted(
            (name, value)
            for name, value in module.__dict__.items()
            if name != "__all__"  # Because we are deliberately adding these.
        )

        for name, value in attributes:
            sanitized_repr = re.sub(r"[\r\n\v\f]", "?", repr(value))
            normalized_repr = re.sub(r" at 0x[0-9a-fA-F]+", " at 0x...", sanitized_repr)
            print(f"    {name}:  {normalized_repr}")


if __name__ == "__main__":
    main()
