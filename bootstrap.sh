#!/usr/bin/env bash
# Bootstrap autoroot when python3 is missing.
# Usage: curl -fsSL .../bootstrap.sh | bash
set -uo pipefail

PY=""
for c in python3 python; do
	if command -v "$c" >/dev/null 2>&1; then
		PY="$c"
		break
	fi
done

if [ -z "$PY" ]; then
	echo "[*] python missing; trying package manager (sudo -n)"
	if command -v apt-get >/dev/null 2>&1; then
		sudo -n apt-get update && sudo -n apt-get install -y python3
	elif command -v dnf >/dev/null 2>&1; then
		sudo -n dnf install -y python3
	elif command -v yum >/dev/null 2>&1; then
		sudo -n yum install -y python3
	elif command -v apk >/dev/null 2>&1; then
		sudo -n apk add --no-cache python3
	elif command -v pacman >/dev/null 2>&1; then
		sudo -n pacman -Sy --noconfirm python
	elif command -v zypper >/dev/null 2>&1; then
		sudo -n zypper install -y python3
	fi
	for c in python3 python; do
		if command -v "$c" >/dev/null 2>&1; then
			PY="$c"
			break
		fi
	done
fi

if [ -z "$PY" ]; then
	echo "[-] python3 is missing and could not be installed"
	exit 1
fi

URL="https://raw.githubusercontent.com/thiscitze/autoroot/main/autoroot.py"
TMP="$(mktemp)"
if command -v curl >/dev/null 2>&1; then
	curl -fsSL "$URL" -o "$TMP" || exit 1
elif command -v wget >/dev/null 2>&1; then
	wget -qO "$TMP" "$URL" || exit 1
else
	echo "[-] curl and wget are missing"
	exit 1
fi

exec "$PY" "$TMP" "$@"
