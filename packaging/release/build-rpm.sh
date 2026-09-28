#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
version="${1:?usage: build-rpm.sh VERSION TARGET [OUTPUT_DIR]}"
target="${2:?usage: build-rpm.sh VERSION TARGET [OUTPUT_DIR]}"
out_dir="${3:-$root_dir/dist}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

mkdir -p "$out_dir"
mkdir -p "$work_dir/rpmbuild"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
sed "s/@VERSION@/${version}/g" \
    "$root_dir/packaging/rpm/gaze-fido.spec.in" \
    > "$work_dir/gaze-fido.spec"

rpmbuild -bb \
    --define "_topdir $work_dir/rpmbuild" \
    --define "project_root $root_dir" \
    "$work_dir/gaze-fido.spec"

mapfile -t built_rpms < <(find "$work_dir/rpmbuild/RPMS" -type f -name '*.rpm' -print)
if [[ "${#built_rpms[@]}" -ne 1 ]]; then
    echo "expected one RPM, found ${#built_rpms[@]}" >&2
    exit 1
fi
output="$out_dir/gaze-fido-${version}-1.${target}.x86_64.rpm"
install -m644 "${built_rpms[0]}" "$output"
printf 'Built %s\n' "$output"
