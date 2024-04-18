#!/usr/bin/env bash
set -euo pipefail

#################
# Prerequisites #
#################

for cmd in python3 git wget rsync; do
  command -v "$cmd" >/dev/null 2>&1 || {
    printf '[%s] Required command %s not found, exiting.\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$cmd" >&2
    exit 1
  }
done

SEED_DATA_DIR="$SRC/seed_data"
mkdir -p "$SEED_DATA_DIR"

#############
# Functions #
#############

download_and_concatenate_common_dictionaries() {
  # Assign the first argument as the target file where all contents will be concatenated
  target_file="$1"

  # Shift the arguments so the first argument (target_file path) is removed
  # and only URLs are left for the loop below.
  shift

  for url in "$@"; do
    wget -qO- "$url" >>"$target_file"
    # Ensure there's a newline between each file's content
    echo >>"$target_file"
  done
}

fetch_seed_corpora() {
  # Seed corpus zip files are hosted in a separate repository to avoid additional bloat in this repo.
  git clone --depth 1 https://github.com/gitpython-developers/qa-assets.git qa-assets &&
    rsync -avc qa-assets/gitpython/corpra/ "$SEED_DATA_DIR/" &&
    rm -rf qa-assets # Clean up the cloned repo to keep the Docker image as slim as possible.
}

########################
# Main execution logic #
########################

fetch_seed_corpora

download_and_concatenate_common_dictionaries "$SEED_DATA_DIR/__base.dict" \
  "https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/utf8.dict" \
  "https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/url.dict"

# The OSS-Fuzz base image has outdated dependencies by default so we upgrade them below.
python3 -m pip install --upgrade pip
# Upgrade to the latest versions known to work at the time the below changes were introduced:
python3 -m pip install 'setuptools~=69.0' 'pyinstaller~=6.0'
