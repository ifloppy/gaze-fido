#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
version="${1:?usage: build-deb.sh VERSION debian13|ubuntu26.04}"
target="${2:?usage: build-deb.sh VERSION debian13|ubuntu26.04}"
case "$target" in
    debian13|ubuntu26.04) ;;
    *) echo "unsupported Debian package target: $target" >&2; exit 2 ;;
esac

out_dir="${3:-$root_dir/dist}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
pkg_root="$work_dir/pkg"
mkdir -p "$pkg_root/DEBIAN"

install -Dm755 "$root_dir/target/release/gaze-fido" \
    "$pkg_root/usr/bin/gaze-fido"
install -Dm755 "$root_dir/target/release/gaze-fido-ui" \
    "$pkg_root/usr/bin/gaze-fido-ui"
install -Dm644 "$root_dir/ui/org.gazefido.gazefido.desktop" \
    "$pkg_root/usr/share/applications/org.gazefido.gazefido.desktop"
install -Dm644 "$root_dir/packaging/arch/gaze-fido-autostart.desktop" \
    "$pkg_root/etc/xdg/autostart/gaze-fido.desktop"
install -Dm644 "$root_dir/packaging/arch/gaze-fido.service" \
    "$pkg_root/usr/lib/systemd/user/gaze-fido.service"
install -Dm644 "$root_dir/packaging/arch/70-gaze-fido.rules" \
    "$pkg_root/usr/lib/udev/rules.d/70-gaze-fido.rules"
install -Dm644 "$root_dir/README.md" \
    "$pkg_root/usr/share/doc/gaze-fido/README.md"
install -Dm644 "$root_dir/docs/THREAT_MODEL.md" \
    "$pkg_root/usr/share/doc/gaze-fido/THREAT_MODEL.md"
install -Dm644 "$root_dir/LICENSE" \
    "$pkg_root/usr/share/doc/gaze-fido/copyright"
install -Dm755 "$root_dir/packaging/debian/postinst" \
    "$pkg_root/DEBIAN/postinst"
install -Dm755 "$root_dir/packaging/debian/postrm" \
    "$pkg_root/DEBIAN/postrm"

mkdir -p "$work_dir/debian"
cat > "$work_dir/debian/control" <<'EOF'
Source: gaze-fido
Section: utils
Priority: optional
Maintainer: Gaze FIDO contributors <ifloppy@users.noreply.github.com>
Standards-Version: 4.7.0

Package: gaze-fido
Architecture: any
Depends: ${shlibs:Depends}
Description: Gaze-verified Linux FIDO2 authenticator
 Uses TPM 2.0 protected keys and Gaze face verification for WebAuthn.
EOF

shlib_output="$(
    cd "$work_dir"
    dpkg-shlibdeps --ignore-missing-info --warnings=0 -O \
        -e "$pkg_root/usr/bin/gaze-fido" \
        -e "$pkg_root/usr/bin/gaze-fido-ui"
)"
shlib_deps="${shlib_output#shlibs:Depends=}"
if [[ -z "$shlib_deps" || "$shlib_deps" == "$shlib_output" ]]; then
    echo "dpkg-shlibdeps did not report shared-library dependencies" >&2
    exit 1
fi

architecture="$(dpkg --print-architecture)"
cat > "$pkg_root/DEBIAN/control" <<EOF
Package: gaze-fido
Version: ${version}-1~${target}
Section: utils
Priority: optional
Architecture: ${architecture}
Maintainer: Gaze FIDO contributors <ifloppy@users.noreply.github.com>
Depends: ${shlib_deps}, qml6-module-qt-labs-platform, qml6-module-qtquick,
 qml6-module-qtquick-controls, qml6-module-qtquick-layouts,
 qml6-module-qtquick-window, qml6-module-org-kde-kirigami, qt6-qpa-plugins
Recommends: qml6-module-org-kde-desktop
Homepage: https://github.com/ifloppy/gaze-fido
Description: Gaze-verified Linux FIDO2 authenticator
 Uses TPM 2.0 protected keys and Gaze face verification for WebAuthn.
EOF

mkdir -p "$out_dir"
output="$out_dir/gaze-fido_${version}-1.${target}_${architecture}.deb"
dpkg-deb --build --root-owner-group "$pkg_root" "$output"
printf 'Built %s\n' "$output"
