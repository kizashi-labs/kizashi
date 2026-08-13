#!/bin/bash
# Install / upgrade / remove test for the Linux agent packages, run inside a
# throwaway container.
#
# Why this exists: nothing else exercises the maintainer scripts. `nfpm package`
# only proves the archive can be built; the postinstall, preremove and
# postremove logic — service account creation, first-run config, and above all
# the uninstall-protection gate — runs for the first time on a customer's host
# unless something like this runs it first.
#
# It has already earned its keep: it caught /var/log/edr and /var/lib/edr being
# deleted by `apt remove` while postremove printed "logs and quarantined files
# kept", because shipping them as package content made the package manager
# their owner. No static check would have found that.
#
# What it cannot show: containers have no systemd, so the postinstall takes its
# documented "systemd not detected" fallback and no service is started. File
# placement, accounts, config generation and the removal gate are all real.
#
# Usage (from the repository root, with Docker running):
#
#   packaging/test/install-test.sh deb    # Debian, dpkg
#   packaging/test/install-test.sh rpm    # Rocky Linux, rpm
#   packaging/test/install-test.sh both
#
# Binaries and packages are built first; pass PKG_DIR to reuse existing ones.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NFPM_DIR="$REPO_ROOT/packaging/nfpm"
PKG_DIR="${PKG_DIR:-$NFPM_DIR/out}"
TARGET="${1:-both}"

build_packages() {
    command -v nfpm >/dev/null 2>&1 || {
        echo "nfpm not found. Install it with:" >&2
        echo "  go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.0" >&2
        exit 1
    }
    echo "==> building linux/amd64 binaries"
    mkdir -p "$NFPM_DIR/bin" "$PKG_DIR"
    (cd "$REPO_ROOT/agent" &&
        GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
            -o "$NFPM_DIR/bin/edr-agent" ./cmd/agent &&
        GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
            -o "$NFPM_DIR/bin/edr-watchdog" ./cmd/watchdog)
    chmod +x "$NFPM_DIR/bin/edr-agent" "$NFPM_DIR/bin/edr-watchdog"

    echo "==> building packages"
    rm -f "$PKG_DIR"/*.deb "$PKG_DIR"/*.rpm
    (cd "$NFPM_DIR" && VERSION=0.0.0-test ARCH=amd64 \
        nfpm package --config agent.yaml --packager deb --target "$PKG_DIR" &&
        VERSION=0.0.0-test ARCH=amd64 \
            nfpm package --config agent.yaml --packager rpm --target "$PKG_DIR")
}

run_in_container() {
    local image="$1" setup="$2" fmt="$3"
    echo
    echo "############ $fmt on $image ############"
    MSYS_NO_PATHCONV=1 docker run --rm \
        -v "$PKG_DIR:/pkg:ro" \
        -v "$REPO_ROOT/packaging/test:/test:ro" \
        -e "PKG_FORMAT=$fmt" \
        "$image" bash -c "$setup; bash /test/container-checks.sh"
}

[ -n "${SKIP_BUILD:-}" ] || build_packages

rc=0
case "$TARGET" in
    deb)  run_in_container debian:bookworm-slim "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3 >/dev/null 2>&1" deb || rc=1 ;;
    rpm)  run_in_container rockylinux:9 "dnf install -y -q python3 shadow-utils >/dev/null 2>&1 || true" rpm || rc=1 ;;
    both)
        run_in_container debian:bookworm-slim "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3 >/dev/null 2>&1" deb || rc=1
        run_in_container rockylinux:9 "dnf install -y -q python3 shadow-utils >/dev/null 2>&1 || true" rpm || rc=1
        ;;
    *) echo "usage: $0 [deb|rpm|both]" >&2; exit 2 ;;
esac

exit "$rc"
