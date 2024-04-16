# Fuzzing GitPython

[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/gitpython.svg)][oss-fuzz-issue-tracker]

This directory contains files related to GitPython's suite of fuzz tests that are executed daily on automated
infrastructure provided by [OSS-Fuzz][oss-fuzz-repo]. This document aims to provide necessary information for working
with fuzzing in GitPython.

The latest details regarding OSS-Fuzz test status, including build logs and coverage reports, is available
on [the Open Source Fuzzing Introspection website](https://introspector.oss-fuzz.com/project-profile?project=gitpython).

## How to Contribute

There are many ways to contribute to GitPython's fuzzing efforts! Contributions are welcomed through issues,
discussions, or pull requests on this repository.

Areas that are particularly appreciated include:

- **Tackling the existing backlog of open issues**. While fuzzing is an effective way to identify bugs, that information
  isn't useful unless they are fixed. If you are not sure where to start, the issues tab is a great place to get ideas!
- **Improvements to this (or other) documentation** make it easier for new contributors to get involved, so even small
  improvements can have a large impact over time. If you see something that could be made easier by a documentation
  update of any size, please consider suggesting it!

For everything else, such as expanding test coverage, optimizing test performance, or enhancing error detection
capabilities, jump into the "Getting Started" section below.

## Getting Started with Fuzzing GitPython

> [!TIP]
> **New to fuzzing or unfamiliar with OSS-Fuzz?**
>
> These resources are an excellent place to start:
>
> - [OSS-Fuzz documentation][oss-fuzz-docs] - Continuous fuzzing service for open source software.
> - [Google/fuzzing][google-fuzzing-repo] - Tutorials, examples, discussions, research proposals, and other resources
    related to fuzzing.
> - [CNCF Fuzzing Handbook](https://github.com/cncf/tag-security/blob/main/security-fuzzing-handbook/handbook-fuzzing.pdf) -
    A comprehensive guide for fuzzing open source software.
> - [Efficient Fuzzing Guide by The Chromium Project](https://chromium.googlesource.com/chromium/src/+/main/testing/libfuzzer/efficient_fuzzing.md) -
    Explores strategies to enhance the effectiveness of your fuzz tests, recommended for those looking to optimize their
    testing efforts.

### Setting Up Your Local Environment

Before contributing to fuzzing efforts, ensure Python and Docker are installed on your machine. Docker is required for
running fuzzers in containers provided by OSS-Fuzz. [Install Docker](https://docs.docker.com/get-docker/) following the
official guide if you do not already have it.

### Understanding Existing Fuzz Targets

Review the `fuzz-targets/` directory to familiarize yourself with how existing tests are implemented. See
the [Files & Directories Overview](#files--directories-overview) for more details on the directory structure.

### Contributing to Fuzz Tests

Start by reviewing the [Atheris documentation][atheris-repo] and the section
on [Running Fuzzers Locally](#running-fuzzers-locally) to begin writing or improving fuzz tests.

## Files & Directories Overview

The `fuzzing/` directory is organized into three key areas:

### Fuzz Targets (`fuzz-targets/`)

Contains Python files for each fuzz test.

**Things to Know**:

- Each fuzz test targets a specific part of GitPython's functionality.
- Test files adhere to the naming convention: `fuzz_<API Under Test>.py`, where `<API Under Test>` indicates the
  functionality targeted by the test.
- Any functionality that involves performing operations on input data is a possible candidate for fuzz testing, but
  features that involve processing untrusted user input or parsing operations are typically going to be the most
  interesting.
- The goal of these tests is to identify previously unknown or unexpected error cases caused by a given input. For that
  reason, fuzz tests should gracefully handle anticipated exception cases with a `try`/`except` block to avoid false
  positives that halt the fuzzing engine.

### Dictionaries (`dictionaries/`)

Provides hints to the fuzzing engine about inputs that might trigger unique code paths. Each fuzz target may have a
corresponding `.dict` file. For information about dictionary syntax, refer to
the [LibFuzzer documentation on the subject](https://llvm.org/docs/LibFuzzer.html#dictionaries).

**Things to Know**:

- OSS-Fuzz loads dictionary files per fuzz target if one exists with the same name, all others are ignored.
- Most entries in the dictionary files found here are escaped hex or Unicode values that were recommended by the fuzzing
  engine after previous runs.
- A default set of dictionary entries are created for all fuzz targets as part of the build process, regardless of an
  existing file here.
- Development or updates to dictionaries should reflect the varied formats and edge cases relevant to the
  functionalities under test.
- Example dictionaries (some of which are used to build the default dictionaries mentioned above) can be found here:
  - [AFL++ dictionary repository](https://github.com/AFLplusplus/AFLplusplus/tree/stable/dictionaries#readme)
  - [Google/fuzzing dictionary repository](https://github.com/google/fuzzing/tree/master/dictionaries)

### OSS-Fuzz Scripts (`oss-fuzz-scripts/`)

Includes scripts for building and integrating fuzz targets with OSS-Fuzz:

- **`container-environment-bootstrap.sh`** - Sets up the execution environment. It is responsible for fetching default
  dictionary entries and ensuring all required build dependencies are installed and up-to-date.
- **`build.sh`** - Executed within the Docker container, this script builds fuzz targets with necessary instrumentation
  and prepares seed corpora and dictionaries for use.

**Where to learn more:**

- [OSS-Fuzz documentation on the build.sh](https://google.github.io/oss-fuzz/getting-started/new-project-guide/#buildsh)
- [See GitPython's build.sh and Dockerfile in the OSS-Fuzz repository](https://github.com/google/oss-fuzz/tree/master/projects/gitpython)

## Running Fuzzers Locally

### Direct Execution of Fuzz Targets

For quick testing of changes, [Atheris][atheris-repo] makes it possible to execute a fuzz target directly:

1. Install Atheris following the [installation guide][atheris-repo] for your operating system.
2. Execute a fuzz target, for example:

```shell
python fuzzing/fuzz-targets/fuzz_config.py
```

### Running OSS-Fuzz Locally

This approach uses Docker images provided by OSS-Fuzz for building and running fuzz tests locally. It offers
comprehensive features but requires a local clone of the OSS-Fuzz repository and sufficient disk space for Docker
containers.

#### Preparation

Set environment variables to simplify command usage:

```shell
# $SANITIZER can be either 'address' or 'undefined':
export SANITIZER=address
# specify the fuzz target without the .py extension:
export FUZZ_TARGET=fuzz_config
```

#### Build and Run

Clone the OSS-Fuzz repository and prepare the Docker environment:

```shell
git clone --depth 1 https://github.com/google/oss-fuzz.git oss-fuzz
cd oss-fuzz
python infra/helper.py build_image gitpython
python infra/helper.py build_fuzzers --sanitizer $SANITIZER gitpython
```

> [!TIP]
> The `build_fuzzers` command above accepts a local file path pointing to your GitPython repository clone as the last
> argument.
> This makes it easy to build fuzz targets you are developing locally in this repository without changing anything in
> the OSS-Fuzz repo!
> For example, if you have cloned this repository (or a fork of it) into: `~/code/GitPython`
> Then running this command would build new or modified fuzz targets using the `~/code/GitPython/fuzzing/fuzz-targets`
> directory:
> ```shell
> python infra/helper.py build_fuzzers --sanitizer $SANITIZER gitpython ~/code/GitPython
> ```


Verify the build of your fuzzers with the optional `check_build` command:

```shell
python infra/helper.py check_build gitpython
```

Execute the desired fuzz target:

```shell
python infra/helper.py run_fuzzer gitpython $FUZZ_TARGET -- -max_total_time=60 -print_final_stats=1
```

> [!TIP]
> In the example above, the "`-- -max_total_time=60 -print_final_stats=1`" portion of the command is optional but quite
> useful.
>
> Every argument provided after "`--`" in the above command is passed to the fuzzing engine directly. In this case:
> - `-max_total_time=60` tells the LibFuzzer to stop execution after 60 seconds have elapsed.
> - `-print_final_stats=1` tells the LibFuzzer to print a summary of useful metrics about the target run upon
    completion.
>
> But almost any [LibFuzzer option listed in the documentation](https://llvm.org/docs/LibFuzzer.html#options) should
> work as well.

#### Next Steps

For detailed instructions on advanced features like reproducing OSS-Fuzz issues or using the Fuzz Introspector, refer
to [the official OSS-Fuzz documentation][oss-fuzz-docs].

## LICENSE

All files located within the `fuzzing/` directory are subject to [the same license](../LICENSE)
as [the other files in this repository](../README.md#license) with two exceptions:

Two files located in this directory, [`fuzz_config.py`](./fuzz-targets/fuzz_config.py)
and [`fuzz_tree.py`](./fuzz-targets/fuzz_tree.py), have been migrated here from the OSS-Fuzz project repository where
they were originally created. As such, these two files retain their original license and copyright notice (Apache
License, Version 2.0 and Copyright 2023 Google LLC respectively.) Each file includes a notice in their respective header
comments stating that they have been modified. [LICENSE-APACHE](./LICENSE-APACHE) contains the original license used by
the OSS-Fuzz project repository at the time they were migrated.

[oss-fuzz-repo]: https://github.com/google/oss-fuzz

[oss-fuzz-docs]: https://google.github.io/oss-fuzz

[oss-fuzz-issue-tracker]: https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:gitpython

[google-fuzzing-repo]: https://github.com/google/fuzzing

[atheris-repo]: https://github.com/google/atheris
