#!/usr/bin/env bash
# Bootstrap autoroot when python3 is missing or too old.
# Usage: curl -fsSL .../bootstrap.sh | bash
set -uo pipefail

PY=""
find_python() {
	for c in python3 python3.11 python3.10 python3.9 python3.8 python3.7 python3.6 python; do
		if command -v "$c" >/dev/null 2>&1; then
			if "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' >/dev/null 2>&1; then
				PY="$c"
				return 0
			fi
		fi
	done
	return 1
}

if ! find_python; then
	echo "[*] python 3.6+ missing; trying package manager (sudo -n)"
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
	find_python || true
fi

if [ -z "$PY" ]; then
	echo "[-] python 3.6+ is missing and could not be installed"
	exit 1
fi

echo "[*] using $PY ($($PY --version 2>&1))"
URL="https://raw.githubusercontent.com/thiscitze/autoroot/main/autoroot.py?v=$(date +%s)"
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
