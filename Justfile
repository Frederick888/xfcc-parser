set shell := ["bash", "+u", "-c"]

default:
    cargo fmt -- --check
    cargo clippy --examples --benches --tests
    cargo test --quiet

lint:
    cargo fmt -- --check
    cargo clippy --examples --benches --tests -- -D warnings

release version:
    set -e
    @if [[ "{{version}}" == v* ]]; then printf 'Must not have v-prefix\n'; exit 1; fi
    # changelog
    if [[ "{{version}}" != *"-"* ]]; then \
        last_tag="$(git tag -l --sort version:refname | grep -v -- - | tail -n1)"; \
        clog --from="$last_tag" --setversion=v{{version}} -o ./CHANGELOG.md; \
        git add ./CHANGELOG.md; \
    fi
    # host
    sed 's/^version = ".*"$/version = "{{version}}"/' -i ./Cargo.toml
    git add ./Cargo.toml
    just lint
    cargo test
    # commit and tag
    git status
    git diff --exit-code
    git commit -m 'chore: Bump version to {{version}}'
    git tag v{{version}}

# vim: set filetype=just :
