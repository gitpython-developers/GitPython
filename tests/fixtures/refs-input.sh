#!/usr/bin/env bash
set -eu
printf 'private tag message' > message
printf 'unmatched-path-one\nunmatched-path-two' > pathspecs
printf 'CHANGES\0' > pathspecs-nul
