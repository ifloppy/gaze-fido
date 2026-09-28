#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
version="${1:?usage: create-source-archive.sh VERSION [OUTPUT_DIR]}"
out_dir="${2:-$root_dir/dist}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

prefix="gaze-fido-${version}"
git -C "$root_dir" archive --format=tar --prefix="${prefix}/" HEAD \
    | tar -xf - -C "$work_dir"
source_dir="$work_dir/$prefix"
mkdir -p "$source_dir/.cargo"
(
    cd "$source_dir"
    cargo vendor --locked --versioned-dirs vendor > .cargo/config.toml
)

mkdir -p "$out_dir"
output="$out_dir/${prefix}-source.tar.gz"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    -cf - -C "$work_dir" "$prefix" | gzip -n > "$output"
printf 'Built %s\n' "$output"
