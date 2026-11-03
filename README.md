# autoroot

Lab privilege-escalation runner. It wraps the public exploit commands into one
script, with environment checks and per-command timeouts.

**Use only on a disposable VM you own.** Some modules are unverified public
repos; some can crash the kernel. A child exploit cannot elevate the parent
Python process, so use a module that leaves a SUID shell or run the exploit
interactively.

## Usage

```bash
python3 autoroot.py --list
python3 autoroot.py --yes
python3 autoroot.py --yes --only pwnkit
python3 autoroot.py --yes --timeout 90
python3 autoroot.py --yes --allow-untrusted --labs
python3 autoroot.py --dry-run
```

- `--list` - show modules and flags.
- `--yes` - required to run anything.
- `--only KEY` - run one module.
- `--dry-run` - print commands without executing.
- `--allow-untrusted` - enable `curl | python3` payloads from unknown hosts.
- `--labs` - include Docker/service lab modules.
- `--timeout N` - per-command timeout (default 45s; 0 = no timeout).
- `--allow-untrusted` is off by default.

## GCC and permission bypasses

The runner tries to keep compile/run steps working on minimal or locked-down
VMs:

- **Compiler fallback:** `gcc` -> `cc` -> `clang` -> `tcc`.
- **Package install:** if none exist, it tries `sudo -n` with apt/dnf/yum/apk/
  pacman/zypper (passwordless sudo only; no prompt).
- **Workdir selection:** `$AUTOROOT_WORK`, `~/.cache/autoroot`, `/dev/shm`,
  `/var/tmp`, `/tmp`; it skips mounts marked `noexec`.
- **noexec retry:** if a compiled binary returns 126 (permission/exec denied),
  it copies the binary to `~/.cache/autoroot-exec` or `/dev/shm/autoroot-exec`
  and retries.
- **Git/tar/curl/make:** missing tools are installed with the same
  passwordless-sudo path.

If the box has no compiler, no package manager, and no writable exec mount,
compile-based modules will skip; there is no userspace trick around that.

## Modules

| Key | Target |
|---|---|
| `pwnkit` | pkexec SUID (CVE-2021-4034) |
| `dirtypipe` | kernel 5.8-5.16 (CVE-2022-0847) |
| `gameover` | Ubuntu OverlayFS (CVE-2023-2640/32629) |
| `overlayfs` | CVE-2023-0386 |
| `dirtyfrag` | kernel 6.1-6.6 |
| `fragnesia` | kernel 5.19-6.8 |
| `packagekit` | PackageKit (CVE-2026-41651) |
| `ovswrap` | Open vSwitch |
| `cve2026_46300` | unknown |
| `diagspill` | unknown |
| `tunderflow` | unknown |
| `cve2026_68138` | unknown |
| `dirtydecrypt` | CVE-2026-31635 |
| `cybermeowfia` | CVE-2026-52923 RHEL lab |
| `cve2026_68398` | unknown |
| `pwnkit2` | PwnKit second repo |
| `cve2026_64600` | unknown |
| `untrusted_copyfail` | `copy.fail` remote script (untrusted) |
| `untrusted_softechnology` | `softechnology.biz` remote script (untrusted) |
| `mariadb_lab` | Docker MariaDB lab |
| `post_suid` | SUID bash, only if already root |
| `recon` | `id`, `sudo -n -l`, kernel, distro |

## Notes

- Kernel/distro checks are coarse; a module can still fail on a patched or
  differently configured host.
- `post_suid` is not a privilege escalation: `cp /bin/bash /tmp/bash` only
  works if the script is already root.
- The two `curl | python3` entries are disabled by default; the domains are
  not verified. Enable only inside an isolated VM.
- Many CVE-2026 entries are unverified public repos. Treat their titles as
  claims, not facts.
- The runner writes to `/tmp/autoroot.*`; remove it when done.

## Suggested lab flow

```bash
# 1. snapshot the VM
python3 autoroot.py --list
python3 autoroot.py --yes --only pwnkit
python3 autoroot.py --yes --only dirtypipe
# 2. inspect results, then try the rest
python3 autoroot.py --yes --timeout 60
```
