#!/usr/bin/env bash
#
# This file is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

set -euo pipefail

#################
# Prerequisites #
#################

for cmd in python3 git wget zip; do
  command -v "$cmd" >/dev/null 2>&1 || {
    printf '[%s] Required command %s not found, exiting.\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$cmd" >&2
    exit 1
  }
done

#############
# Functions #
#############

download_and_concatenate_common_dictionaries() {
  # Assign the first argument as the target file where all contents will be concatenated
  local target_file="$1"

  # Shift the arguments so the first argument (target_file path) is removed
  # and only URLs are left for the loop below.
  shift

  for url in "$@"; do
    wget -qO- "$url" >>"$target_file"
    # Ensure there's a newline between each file's content
    echo >>"$target_file"
  done
}

create_seed_corpora_zips() {
  local seed_corpora_dir="$1"
  local output_zip
  for dir in "$seed_corpora_dir"/*; do
    if [ -d "$dir" ] && [ -n "$dir" ]; then
      output_zip="$SRC/$(basename "$dir")_seed_corpus.zip"
      printf '[%s] Zipping the contents of %s into %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$dir" "$output_zip"
      zip -jur "$output_zip" "$dir"/*
    fi
  done
}

prepare_dictionaries_for_fuzz_targets() {
  local dictionaries_dir="$1"
  local fuzz_targets_dir="$2"
  local common_base_dictionary_filename="$WORK/__base.dict"

  printf '[%s] Copying .dict files from %s to %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"  "$dictionaries_dir" "$SRC/"
  cp -v "$dictionaries_dir"/*.dict "$SRC/"

  download_and_concatenate_common_dictionaries "$common_base_dictionary_filename" \
    "https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/utf8.dict" \
    "https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/url.dict"

  find "$fuzz_targets_dir" -name 'fuzz_*.py' -print0 | while IFS= read -r -d '' fuzz_harness; do
    if [[ -r "$common_base_dictionary_filename" ]]; then
      # Strip the `.py` extension from the filename and replace it with `.dict`.
      fuzz_harness_dictionary_filename="$(basename "$fuzz_harness" .py).dict"
      local output_file="$SRC/$fuzz_harness_dictionary_filename"

      printf '[%s] Appending %s to %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$common_base_dictionary_filename" "$output_file"
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
}

########################
# Main execution logic #
########################
# Seed corpora and dictionaries are hosted in a separate repository to avoid additional bloat in this repo.
# We clone into the $WORK directory because OSS-Fuzz cleans it up after building the image, keeping the image small.
git clone --depth 1 https://github.com/gitpython-developers/qa-assets.git "$WORK/qa-assets"

create_seed_corpora_zips "$WORK/qa-assets/gitpython/corpora"

prepare_dictionaries_for_fuzz_targets "$WORK/qa-assets/gitpython/dictionaries" "$SRC/gitpython/fuzzing"

pushd "$SRC/gitpython/"
# Search for 'raise' and 'assert' statements in Python files within GitPython's source code and submodules, saving the
# matched file path, line number, and line content to a file named 'explicit-exceptions-list.txt'.
# This file can then be used by fuzz harnesses to check exception tracebacks and filter out explicitly raised or otherwise
# anticipated exceptions to reduce false positive test failures.

git grep -n --recurse-submodules -e '\braise\b' -e '\bassert\b' -- '*.py' -- ':!setup.py' -- ':!test/**' -- ':!fuzzing/**' > "$SRC/explicit-exceptions-list.txt"

popd


# The OSS-Fuzz base image has outdated dependencies by default so we upgrade them below.
python3 -m pip install --upgrade pip
# Upgrade to the latest versions known to work at the time the below changes were introduced:
python3 -m pip install 'setuptools~=69.0' 'pyinstaller~=6.0'
