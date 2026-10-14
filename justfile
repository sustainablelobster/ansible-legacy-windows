set shell := ["bash", "--norc", "-euo", "pipefail", "-c"]

default:
    @just --list

# Install commit hooks explicitly from inside nix develop.
setup:
    pre-commit install

# Run the same Nix-provided tools used by commit hooks.
lint:
    git ls-files -z --cached --others --exclude-standard | xargs -0 -r pre-commit run --files

# Refresh local collections before lint tools resolve their installed namespaces.
_install-lint-collections:
    ANSIBLE_COLLECTIONS_PATH="$PWD/.ansible/collections" ansible-galaxy collection install legacy_windows --offline --no-deps --force --collections-path .ansible/collections
    ANSIBLE_COLLECTIONS_PATH="$PWD/.ansible/collections" ansible-galaxy collection install legacy_ad --offline --no-deps --force --collections-path .ansible/collections

[positional-arguments]
_ansible-lint *args:
    ANSIBLE_COLLECTIONS_PATH="$PWD/.ansible/collections" ansible-lint "$@"

_lint-justfile:
    just --unstable --check --fmt
    just --summary > /dev/null

# Build both collections, or select one; replace only that version's artifact.
[positional-arguments]
build collection="all":
    #!/usr/bin/env bash
    set -euo pipefail
    case "$1" in
        all) collection_sources=(legacy_windows legacy_ad) ;;
        legacy_windows) collection_sources=(legacy_windows) ;;
        legacy_ad) collection_sources=(legacy_ad) ;;
        *) echo 'Choose all, legacy_windows, or legacy_ad.' >&2; exit 2 ;;
    esac
    for collection_source in "${collection_sources[@]}"; do
        ansible-galaxy collection build "$collection_source" --output-path dist --force
    done

# Inspect selected archives and resolve AD's Windows dependency without hosts.
[positional-arguments]
check collection="all":
    python scripts/check_collection.py --collection "$1"
