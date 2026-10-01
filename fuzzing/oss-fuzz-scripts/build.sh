# shellcheck shell=bash
#
# This file is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

set -euo pipefail

git_binary="$(command -v git)" || {
  printf 'GitPython fuzzing requires Git 2.52 or newer; git was not found on PATH.\n' >&2
  exit 1
}
git_version="$("$git_binary" --version)"
if [[ ! "$git_version" =~ ^git\ version\ ([0-9]+)\.([0-9]+)(\.|[[:space:]]|$) ]] ||
  ((10#${BASH_REMATCH[1]} < 2 || (10#${BASH_REMATCH[1]} == 2 && 10#${BASH_REMATCH[2]} < 52))); then
  printf 'GitPython fuzzing requires Git 2.52 or newer; %s reports %s. Update the container Git installation.\n' \
    "$git_binary" "$git_version" >&2
  exit 1
fi

python3 -m pip install .

find "$SRC" -maxdepth 1 \
  \( -name '*_seed_corpus.zip' -o -name '*.options' -o -name '*.dict' \) \
  -exec printf '[%s] Copying: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" {} \; \
  -exec chmod a-x {} \; \
  -exec cp {} "$OUT" \;

# Build fuzzers in $OUT.
find "$SRC/gitpython/fuzzing" -name 'fuzz_*.py' -print0 | while IFS= read -r -d '' fuzz_harness; do
  compile_python_fuzzer "$fuzz_harness" --add-binary="$git_binary:." --add-data="$SRC/explicit-exceptions-list.txt:."
done
