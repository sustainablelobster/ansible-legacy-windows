set shell := ["bash", "--norc", "-euo", "pipefail", "-c"]

default:
    @just --list

# Install commit hooks explicitly from inside nix develop.
setup:
    pre-commit install

# Run the same Nix-provided tools used by commit hooks.
lint:
    pre-commit run --all-files

_lint-justfile:
    just --unstable --check --fmt
    just --summary > /dev/null

# Build the distributable collection, replacing this version's previous artifact.
build:
    ansible-galaxy collection build --output-path dist --force

# Build, inspect, and install locally without accessing any Windows host.
check:
    python scripts/check_collection.py
