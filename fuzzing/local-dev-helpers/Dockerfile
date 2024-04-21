# syntax=docker/dockerfile:1

# Use the same Python version as OSS-Fuzz to accidental incompatibilities in test code
FROM python:3.8-bookworm

LABEL project="GitPython Fuzzing Local Dev Helper"

WORKDIR /src

COPY . .

# Update package managers, install necessary packages, and cleanup unnecessary files in a single RUN to keep the image smaller.
RUN apt-get update && \
    apt-get install -y git clang && \
    python -m pip install --upgrade pip && \
    python -m pip install atheris && \
    python -m pip install -e . && \
    apt-get clean && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

CMD ["bash"]
