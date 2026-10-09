set shell := ["bash", "--norc", "-euo", "pipefail", "-c"]

default:
    @just --list

# Install commit hooks explicitly from inside nix develop.
setup:
    pre-commit install

# Run the same Nix-provided tools used by commit hooks.
lint:
    git ls-files -z --cached --others --exclude-standard | xargs -0 -r pre-commit run --files

# Refresh the current collection before offline module resolution.
[positional-arguments]
_ansible-lint *args:
    ANSIBLE_COLLECTIONS_PATH="$PWD/.ansible/collections" ansible-galaxy collection install . --offline --no-deps --force --collections-path .ansible/collections
    ANSIBLE_COLLECTIONS_PATH="$PWD/.ansible/collections" ansible-lint "$@"

_lint-justfile:
    just --unstable --check --fmt
    just --summary > /dev/null

# Build the distributable collection, replacing this version's previous artifact.
build:
    ansible-galaxy collection build --output-path dist --force

# Build, inspect, and install locally without accessing any Windows host.
check:
    python scripts/check_collection.py
