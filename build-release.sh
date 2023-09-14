#!/bin/bash
#
# This script builds a release. If run in a venv, it auto-installs its tools.
# You may want to run "make release" instead of running this script directly.

set -eEu

if test -n "${VIRTUAL_ENV:-}"; then
    deps=(build twine)  # Install twine along with build, as we need it later.
    printf 'Virtual environment detected. Adding packages: %s\n' "${deps[*]}"
    pip install -U "${deps[@]}"
    printf 'Starting the build.\n'
    python -m build --sdist --wheel
else
    suggest_venv() {
        venv_cmd='python -m venv env && source env/bin/activate'
        printf "Use a virtual-env with '%s' instead.\n" "$venv_cmd"
    }
    trap suggest_venv ERR  # This keeps the original exit (error) code.
    printf 'Starting the build.\n'
    python3 -m build --sdist --wheel  # Outside a venv, use python3.
fi
