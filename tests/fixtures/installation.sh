#!/usr/bin/env bash
set -eu

gix_testtools_require_symlinks
python=$1
platform=$2
source=$3
"$python" -m venv env
if test "$platform" = win32; then
    interpreter=env/Scripts/python.exe
else
    interpreter=env/bin/python
fi
"$interpreter" -m pip install --upgrade pip 'setuptools; python_version<"3.12"'
ln -s "$source" env/src
