# shellcheck shell=bash
#
# This file is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

set -euo pipefail

python3 -m pip install .

find "$SRC" -maxdepth 1 \
  \( -name '*_seed_corpus.zip' -o -name '*.options' -o -name '*.dict' \) \
  -exec printf '[%s] Copying: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" {} \; \
  -exec chmod a-x {} \; \
  -exec cp {} "$OUT" \;

# Build fuzzers in $OUT.
find "$SRC/gitpython/fuzzing" -name 'fuzz_*.py' -print0 | while IFS= read -r -d '' fuzz_harness; do
  compile_python_fuzzer "$fuzz_harness" --add-binary="$(command -v git):." --add-data="$SRC/explicit-exceptions-list.txt:."
done
