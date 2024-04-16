# shellcheck shell=bash

set -euo pipefail

python3 -m pip install .

# Directory to look in for dictionaries, options files, and seed corpora:
SEED_DATA_DIR="$SRC/seed_data"

find "$SEED_DATA_DIR" \( -name '*_seed_corpus.zip' -o -name '*.options' -o -name '*.dict' \) \
  ! \( -name '__base.*' \) -exec printf 'Copying: %s\n' {} \; \
  -exec chmod a-x {} \; \
  -exec cp {} "$OUT" \;

# Build fuzzers in $OUT.
find "$SRC/gitpython/fuzzing" -name 'fuzz_*.py' -print0 | while IFS= read -r -d '' fuzz_harness; do
  compile_python_fuzzer "$fuzz_harness"

  common_base_dictionary_filename="$SEED_DATA_DIR/__base.dict"
  if [[ -r "$common_base_dictionary_filename" ]]; then
    # Strip the `.py` extension from the filename and replace it with `.dict`.
    fuzz_harness_dictionary_filename="$(basename "$fuzz_harness" .py).dict"
    output_file="$OUT/$fuzz_harness_dictionary_filename"

    printf 'Appending %s to %s\n' "$common_base_dictionary_filename" "$output_file"
    if [[ -s "$output_file" ]]; then
      # If a dictionary file for this fuzzer already exists and is not empty,
      # we append a new line to the end of it before appending any new entries.
      #
      # LibFuzzer will happily ignore multiple empty lines in a dictionary but fail with an error
      # if any single line has incorrect syntax (e.g., if we accidentally add two entries to the same line.)
      # See docs for valid syntax: https://llvm.org/docs/LibFuzzer.html#id32
      echo >>"$output_file"
    fi
    cat "$common_base_dictionary_filename" >>"$output_file"
  fi
done
