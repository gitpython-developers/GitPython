#!/usr/bin/env bash
set -eu
# Tutorial pushes must target a disposable copy of the shared example history.
git clone -q --bare "$1" source
