#!/usr/bin/env bash
set -eu
mkdir -p source/git source/test/performance
printf '1.0\n' > source/VERSION
printf 'value = 1\n' > source/git/module.py
printf 'value = 1\n' > source/test/performance/bench_repository.py
cp -R source copy
cp -R source moved
cp -R source harness
printf 'value = 2\n' > copy/git/module.py
printf 'value = 2\n' > harness/test/performance/bench_repository.py
