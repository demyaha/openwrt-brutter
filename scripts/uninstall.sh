#!/bin/sh
# Removes Ping Brutter from the router. --purge also deletes its settings and
# saved servers.
set -eu

[ "$(id -u)" = 0 ] || {
	echo "brutter: run this as root on the router" >&2
	exit 1
}

if [ -x /etc/init.d/brutter ]; then
	/etc/init.d/brutter stop >/dev/null 2>&1 || true
	/etc/init.d/brutter disable >/dev/null 2>&1 || true
fi
rm -f /usr/bin/brutter /etc/init.d/brutter /etc/sysctl.d/90-brutter.conf

if [ -f /etc/nftables.d/20-brutter.nft ]; then
	rm -f /etc/nftables.d/20-brutter.nft
	fw4 reload >/dev/null 2>&1 || true
fi
# Stopping removes these; a crash could have left some behind.
for table in $(nft list tables ip 2>/dev/null | awk '$3 ~ /^brutter_/ { print $3 }'); do
	nft delete table ip "$table"
done

if [ "${1:-}" = --purge ]; then
	rm -f /etc/ping-brutter.json /root/ping-brutter-*.json
	echo "Ping Brutter and its data removed."
else
	echo "Ping Brutter removed. Settings and saved servers are kept; add --purge to delete them."
fi
