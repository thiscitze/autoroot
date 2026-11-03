#!/usr/bin/env bash
# autoroot bootstrap: run the tool even when python3 is missing, too old,
# or broken.  No root and no package manager are required.
#
#   curl -fsSL .../bootstrap.sh | bash
#   curl -fsSL .../bootstrap.sh | bash -s -- --raw --only dirtypipe
#   AUTOROOT_REF=<commit> ./bootstrap.sh
#
# Order of attempts:
#   1. any usable python3/python >= 3.6 already on the box (many locations)
#   2. install python3 with passwordless sudo (apt/dnf/yum/apk/pacman/zypper)
#   3. download a standalone CPython build into $HOME/.cache (no root)
#   4. fall back to /dev/shm or /tmp for that download
set -uo pipefail

REF="${AUTOROOT_REF:-main}"
ARGS=("$@")
PY=""

say() { printf '%s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# Some shells (web terminals, `sudo -u`, cron) run with HOME unset; `set -u`
# would abort on the first "$HOME".  Recover it from the password database.
if [ -z "${HOME:-}" ] || [ ! -d "${HOME:-}" ]; then
	HOME="$(cd ~ 2>/dev/null && pwd)" || HOME=""
	if [ -z "$HOME" ] || [ ! -d "$HOME" ]; then
		HOME="$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6)"
	fi
	if [ -z "$HOME" ] || [ ! -d "$HOME" ]; then
		HOME="/tmp"
	fi
	export HOME
	say "[*] HOME was unset; using $HOME"
fi

py_ok() {
	[ -n "${1:-}" ] && [ -x "$1" ] || return 1
	"$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' \
		>/dev/null 2>&1
}

find_python() {
	local c p
	for c in python3 python3.13 python3.12 python3.11 python3.10 \
		python3.9 python3.8 python3.7 python3.6 python; do
		p="$(command -v "$c" 2>/dev/null)" || continue
		if py_ok "$p"; then PY="$p"; return 0; fi
	done
	# Non-PATH installs: RHEL platform-python, cPanel, Plesk, pyenv, conda.
	for p in \
		/usr/libexec/platform-python \
		/usr/local/bin/python3 \
		/usr/local/bin/python3.12 \
		/usr/local/bin/python3.11 \
		/usr/local/bin/python3.9 \
		/opt/cpanel/ea-python*/root/usr/bin/python3 \
		/opt/plesk/python*/bin/python3 \
		/opt/plesk/python3/bin/python3 \
		"$HOME/.local/bin/python3" \
		"$HOME/.pyenv/shims/python3" \
		"$HOME/.pyenv/versions/"*/bin/python3 \
		/opt/miniconda3/bin/python3 \
		/opt/anaconda3/bin/python3; do
		if py_ok "$p"; then PY="$p"; return 0; fi
	done
	return 1
}

install_pkg_python() {
	command -v sudo >/dev/null 2>&1 || return 1
	if have apt-get; then
		sudo -n apt-get update >/dev/null 2>&1
		sudo -n apt-get install -y python3 >/dev/null 2>&1
	elif have dnf; then
		sudo -n dnf install -y python3 >/dev/null 2>&1
	elif have yum; then
		sudo -n yum install -y python3 >/dev/null 2>&1
	elif have apk; then
		sudo -n apk add --no-cache python3 >/dev/null 2>&1
	elif have pacman; then
		sudo -n pacman -Sy --noconfirm python >/dev/null 2>&1
	elif have zypper; then
		sudo -n zypper install -y python3 >/dev/null 2>&1
	else
		return 1
	fi
	find_python
}

# Fully static CPython (python-build-standalone).  Works on old glibc,
# containers and locked-down boxes without root.
install_static_python() {
	local arch tag="20261026" ver="3.12.16" libc url dir
	case "$(uname -m)" in
		x86_64|amd64) arch="x86_64" ;;
		aarch64|arm64) arch="aarch64" ;;
		*) return 1 ;;
	esac
	for libc in musl gnu; do
		url="https://github.com/astral-sh/python-build-standalone/releases/download/${tag}/cpython-${ver}+${tag}-${arch}-unknown-linux-${libc}-install_only.tar.gz"
		for dir in "$HOME/.cache/autoroot-py" "/dev/shm/autoroot-py" \
			"/tmp/autoroot-py"; do
			mkdir -p "$dir" 2>/dev/null || continue
			say "[*] downloading standalone python 3.12 (${libc}) ..."
			if have curl; then
				curl -fsSL "$url" -o "$dir/py.tgz" 2>/dev/null || continue
			elif have wget; then
				wget -qO "$dir/py.tgz" "$url" 2>/dev/null || continue
			else
				return 1
			fi
			if have tar; then
				tar xzf "$dir/py.tgz" -C "$dir" 2>/dev/null || continue
			elif have busybox; then
				busybox tar xzf "$dir/py.tgz" -C "$dir" 2>/dev/null || continue
			else
				return 1
			fi
			if py_ok "$dir/python/bin/python3"; then
				PY="$dir/python/bin/python3"
				return 0
			fi
		done
	done
	return 1
}

download() {
	local url="$1" out="$2"
	if have curl; then
		curl -fsSL "$url" -o "$out" && return 0
	fi
	if have wget; then
		wget -qO "$out" "$url" && return 0
	fi
	if [ -n "$PY" ]; then
		"$PY" - "$url" "$out" <<'EOF' && return 0
import sys, urllib.request
urllib.request.urlretrieve(sys.argv[1], sys.argv[2])
EOF
	fi
	return 1
}

if ! find_python; then
	say "[*] no python 3.6+ found; trying package manager (sudo -n)"
	install_pkg_python || true
fi

if [ -z "$PY" ]; then
	say "[*] still no python; using standalone build (no root needed)"
	install_static_python || true
fi

if [ -z "$PY" ]; then
	say "[-] python 3.6+ is unavailable and could not be bootstrapped"
	say "    install python3 manually, then run: python3 autoroot.py"
	exit 1
fi

say "[*] python: $PY ($("$PY" --version 2>&1))"

URL="https://raw.githubusercontent.com/thiscitze/autoroot/${REF}/autoroot.py?v=$(date +%s)"
TMP=""
for d in "$HOME/.cache/autoroot" "/dev/shm/autoroot" "/tmp"; do
	mkdir -p "$d" 2>/dev/null || continue
	[ -w "$d" ] || continue
	TMP="$d/autoroot.py"
	break
done
[ -n "$TMP" ] || TMP="$(mktemp 2>/dev/null || echo "/tmp/autoroot.$$.py")"
rm -f "$TMP" 2>/dev/null
if ! download "$URL" "$TMP" || [ ! -s "$TMP" ]; then
	say "[-] could not download autoroot.py"
	exit 1
fi

if [ "${#ARGS[@]}" -gt 0 ]; then
	exec "$PY" "$TMP" "${ARGS[@]}"
fi
exec "$PY" "$TMP"
