#!/bin/sh
# Installs or upgrades Ping Brutter on OpenWrt. Run on the router as root:
#   sh -c "$(wget -qO- https://raw.githubusercontent.com/demyaha/openwrt-brutter/main/scripts/install.sh)"
# BRUTTER_VERSION=v0.1.0 picks a release (default: the latest).
# BRUTTER_BINARY=/tmp/brutter installs a local build with the init script next
# to this file instead of downloading.
set -eu

REPO=${BRUTTER_REPO:-demyaha/openwrt-brutter}
VERSION=${BRUTTER_VERSION:-latest}
CONFIG=/etc/ping-brutter.json

say() { printf '%s\n' "$*"; }
die() {
	printf 'brutter: %s\n' "$*" >&2
	exit 1
}

[ "$(id -u)" = 0 ] || die "run this as root on the router"
[ -f /etc/openwrt_release ] || die "this is not OpenWrt"
. /etc/openwrt_release
command -v nft >/dev/null || die "nftables is missing: Brutter needs OpenWrt 22.03 or newer (firewall4)"

case "${DISTRIB_ARCH:-$(uname -m)}" in
aarch64*) target=arm64 ;;
arm_cortex-a* | armv7*) target=armv7 ;;
arm_* | armv5* | armv6*) target=armv5 ;;
mipsel_*) target=mipsle ;;
mips_*) target=mips ;;
x86_64*) target=amd64 ;;
i386* | i486* | i586* | i686*) target=386 ;;
*) die "unsupported architecture: ${DISTRIB_ARCH:-$(uname -m)}" ;;
esac

free=$(df -k /overlay 2>/dev/null | awk 'NR == 2 { print $4 }')
if [ -n "$free" ] && [ "$free" -lt 4096 ]; then
	die "about 4 MB of free flash is needed, ${free} KB available"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fetch() { # file
	wget -qO "$tmp/$1" "$base/$1" || die "could not download $1 from $base"
	sum=$(awk -v f="$1" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
	[ -n "$sum" ] && [ "$(sha256sum "$tmp/$1" | cut -d' ' -f1)" = "$sum" ] || die "checksum mismatch for $1"
}

if [ -n "${BRUTTER_BINARY:-}" ]; then
	cp "$BRUTTER_BINARY" "$tmp/brutter"
	cp "$(dirname "$0")/../init.d/brutter" "$tmp/brutter.init"
else
	if [ "$VERSION" = latest ]; then
		base="https://github.com/$REPO/releases/latest/download"
	else
		base="https://github.com/$REPO/releases/download/$VERSION"
	fi
	say "Downloading Ping Brutter ($VERSION, $target)..."
	wget -qO "$tmp/SHA256SUMS" "$base/SHA256SUMS" || die "could not reach $base"
	fetch "brutter-linux-$target"
	fetch brutter.init
	mv "$tmp/brutter-linux-$target" "$tmp/brutter"
fi
chmod 755 "$tmp/brutter"
"$tmp/brutter" -version >/dev/null 2>&1 || die "the binary does not run on this router ($target)"

if command -v apk >/dev/null; then
	has() { apk info -e "$1" >/dev/null 2>&1; }
	add() { apk update >/dev/null && apk add "$1" >/dev/null; }
else
	has() { opkg list-installed "$1" 2>/dev/null | grep -q .; }
	add() { opkg update >/dev/null && opkg install "$1" >/dev/null; }
fi
if ! has kmod-nf-conntrack-netlink; then
	say "Installing kmod-nf-conntrack-netlink..."
	add kmod-nf-conntrack-netlink || die "could not install kmod-nf-conntrack-netlink"
fi

# Brutter reads per-connection packet counters.
if [ "$(sysctl -n net.netfilter.nf_conntrack_acct 2>/dev/null)" != 1 ]; then
	sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null
	echo 'net.netfilter.nf_conntrack_acct=1' >/etc/sysctl.d/90-brutter.conf
fi

[ -x /etc/init.d/brutter ] && /etc/init.d/brutter stop >/dev/null 2>&1 || true
cp "$tmp/brutter" /usr/bin/brutter
cp "$tmp/brutter.init" /etc/init.d/brutter
chmod 755 /usr/bin/brutter /etc/init.d/brutter
if [ ! -f "$CONFIG" ]; then
	cat >"$CONFIG" <<'EOF'
{
  "clients": [],
  "port": 1337,
  "lan_interface": "br-lan",
  "state_dir": "/root",
  "ram_dir": "/tmp"
}
EOF
	chmod 600 "$CONFIG"
fi
/etc/init.d/brutter enable
/etc/init.d/brutter start

sleep 3
pgrep -f /usr/bin/brutter >/dev/null || die "Brutter did not start; see: logread -e brutter"
lan=$(ip -4 addr show dev br-lan 2>/dev/null | awk '/inet / { sub(/\/.*/, "", $2); print $2; exit }')
port=$(sed -n 's/.*"port": *\([0-9]*\).*/\1/p' "$CONFIG")
say "Ping Brutter $(/usr/bin/brutter -version) is running: http://${lan:-your-router}:${port:-1337}/"
say "Open it and pick your gaming devices under Devices."
