"""One-shot deployer used from the dev machine.

Connects over SSH (paramiko), inspects the router, ships the project
tree as a tar stream piped into `tar -xz` on the router (Dropbear/BusyBox
ssh servers usually don't expose SFTP), then runs scripts/install.sh.

Developer convenience — NOT part of what ships to the router. Run with:
    python scripts/deploy.py <router-ip> --port <ssh-port> \\
                             --user root --password <your-password>
    # Add --install-deps on first run to opkg install python3 + cryptography.
"""
from __future__ import annotations

import argparse
import io
import os
import posixpath
import sys
import tarfile
import time
from pathlib import Path
from typing import List, Tuple

import paramiko


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REMOTE_TMP = "/opt/tmp/tg-ws-keenetic"

# Paths in the project that should be copied to the router.
INCLUDE = ("tgwsproxy", "webui", "etc", "scripts", "README.md", "INSTALL.md", "LICENSE")
EXCLUDE_NAMES = {"__pycache__", ".git", "_reference", "_stub_check"}


def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m"


def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m"


def _yellow(s: str) -> str:
    return f"\033[33m{s}\033[0m"


def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("host", help="Router IP or hostname")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--user", default="root")
    p.add_argument("--password", required=True)
    p.add_argument("--remote", default=DEFAULT_REMOTE_TMP,
                   help="Remote scratch directory")
    p.add_argument("--skip-inspect", action="store_true",
                   help="Skip environment inspection")
    p.add_argument("--skip-install", action="store_true",
                   help="Copy files only, do not run install.sh")
    p.add_argument("--install-deps", action="store_true",
                   help="Run opkg install for missing packages before deploy")
    return p.parse_args()


def connect(args: argparse.Namespace) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(_bold(f"[ssh] connecting to {args.user}@{args.host}:{args.port}"))
    client.connect(
        hostname=args.host,
        port=args.port,
        username=args.user,
        password=args.password,
        allow_agent=False,
        look_for_keys=False,
        timeout=15,
        banner_timeout=15,
    )
    return client


def run(client: paramiko.SSHClient, command: str, *,
        echo: bool = True, check: bool = False) -> Tuple[int, str, str]:
    if echo:
        print(f"  $ {command}")
    stdin, stdout, stderr = client.exec_command(command, get_pty=False)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    if check and rc != 0:
        sys.stderr.write(out)
        sys.stderr.write(err)
        raise RuntimeError(f"command failed (rc={rc}): {command}")
    return rc, out.strip(), err.strip()


def inspect(client: paramiko.SSHClient) -> dict:
    print(_bold("[inspect] router environment"))
    findings = {}

    rc, uname, _ = run(client, "uname -a", echo=False)
    findings["uname"] = uname
    print(f"  uname: {uname}")

    rc, opt, _ = run(client, "df -P /opt | tail -n1", echo=False)
    findings["opt_mount"] = opt
    print(f"  /opt:  {opt}")

    rc, opkg_v, _ = run(client, "opkg --version 2>&1 | head -n1", echo=False)
    findings["opkg"] = opkg_v
    print(f"  opkg:  {opkg_v}")

    rc, py, _ = run(client, "command -v python3", echo=False)
    findings["python3"] = py or "(missing)"
    if py:
        rc, py_v, _ = run(client, f"{py} --version 2>&1", echo=False)
        findings["python3_version"] = py_v
        print(f"  python3: {py} ({py_v})")
    else:
        print(f"  python3: {_red('not found')}")

    rc, crypto_v, _ = run(
        client,
        "python3 -c 'import cryptography; print(cryptography.__version__)' 2>&1",
        echo=False,
    )
    if rc == 0:
        findings["cryptography"] = crypto_v
        print(f"  cryptography: {crypto_v}")
    else:
        findings["cryptography"] = None
        print(f"  cryptography: {_red('not installed')}  ({crypto_v})")

    rc, p1, _ = run(client, "netstat -lnt 2>/dev/null | grep -E ':1433|:1434' || true", echo=False)
    findings["ports_in_use"] = p1
    if p1:
        print(f"  ports 1433/1434 already bound:")
        for line in p1.splitlines():
            print(f"    {line}")
    else:
        print(f"  ports 1433/1434: free")

    rc, existing, _ = run(
        client,
        "ls /opt/etc/init.d/S99tgwsproxy /opt/share/tgwsproxy 2>/dev/null || true",
        echo=False,
    )
    if existing:
        print(_yellow(f"  prior install detected:\n    {existing}"))
        findings["prior_install"] = existing
    else:
        findings["prior_install"] = None

    return findings


def install_deps(client: paramiko.SSHClient, findings: dict) -> None:
    print(_bold("[opkg] installing missing dependencies"))
    needs = []
    if not findings.get("python3"):
        needs.append("python3")
    if not findings.get("cryptography"):
        needs.append("python3-cryptography")
    if not needs:
        print("  nothing to install")
        return
    run(client, "opkg update", check=True)
    run(client, f"opkg install {' '.join(needs)}", check=True)


def list_files() -> List[Tuple[Path, str]]:
    """Yield (local_path, remote_relpath) pairs in deterministic order."""
    out: List[Tuple[Path, str]] = []
    for entry in INCLUDE:
        local = PROJECT_ROOT / entry
        if local.is_file():
            out.append((local, entry))
            continue
        if not local.is_dir():
            continue
        for path in sorted(local.rglob("*")):
            if path.is_dir():
                continue
            if any(part in EXCLUDE_NAMES for part in path.parts):
                continue
            rel = path.relative_to(PROJECT_ROOT).as_posix()
            out.append((path, rel))
    return out


def _build_tarball(files: List[Tuple[Path, str]]) -> bytes:
    """Pack files into an in-memory gzipped tarball preserving LF endings."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for local, rel in files:
            with open(local, "rb") as fh:
                data = fh.read()
            if rel.endswith((".sh", ".py")) or rel.endswith("S99tgwsproxy"):
                data = data.replace(b"\r\n", b"\n")
            info = tarfile.TarInfo(name=rel)
            info.size = len(data)
            info.mtime = int(time.time())
            info.mode = 0o755 if (
                rel.endswith(".sh") or rel.endswith("S99tgwsproxy")
            ) else 0o644
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def upload(client: paramiko.SSHClient, remote_root: str) -> int:
    files = list_files()
    print(_bold(
        f"[upload] streaming {len(files)} files to {remote_root} via tar"
    ))

    # Wipe & recreate the staging dir so leftovers from previous runs go away.
    run(client, f"rm -rf {remote_root}", echo=False, check=True)
    run(client, f"mkdir -p {remote_root}", echo=False, check=True)

    tarball = _build_tarball(files)
    print(f"  tarball: {len(tarball)} bytes")

    transport = client.get_transport()
    assert transport is not None
    channel = transport.open_session()
    channel.exec_command(f"tar -xzf - -C {remote_root}")
    channel.sendall(tarball)
    channel.shutdown_write()
    out = channel.makefile("r").read()
    err = channel.makefile_stderr("r").read()
    rc = channel.recv_exit_status()
    if out:
        print(out.strip())
    if err:
        sys.stderr.write(err)
    if rc != 0:
        raise RuntimeError(f"remote tar exited with {rc}")
    return len(files)


def run_install(client: paramiko.SSHClient, remote_root: str) -> None:
    print(_bold("[install] running scripts/install.sh"))
    rc, out, err = run(
        client,
        f"cd {remote_root} && sh scripts/install.sh 2>&1",
    )
    print(out)
    if err:
        print(_red("[stderr]"))
        print(err)
    if rc != 0:
        raise SystemExit(f"install.sh failed with exit code {rc}")


def status_check(client: paramiko.SSHClient) -> None:
    print(_bold("[verify] service status"))
    run(client, "/opt/etc/init.d/S99tgwsproxy status || true")
    print()
    print(_bold("[verify] listening ports"))
    run(client, "netstat -lnt 2>/dev/null | grep -E ':1433|:1434' || echo '(no ports yet)'")
    print()
    print(_bold("[verify] last log lines"))
    run(client, "tail -n 20 /opt/var/log/tgwsproxy/stdout.log 2>/dev/null || echo '(no stdout log)'")
    run(client, "tail -n 20 /opt/var/log/tgwsproxy/tgwsproxy.log 2>/dev/null || echo '(no app log)'")


def main() -> int:
    args = parse_args()
    client = connect(args)
    try:
        findings = {}
        if not args.skip_inspect:
            findings = inspect(client)
            missing_blockers = []
            if not findings.get("python3"):
                missing_blockers.append("python3")
            if not findings.get("cryptography"):
                missing_blockers.append("python3-cryptography")
            if missing_blockers:
                if args.install_deps:
                    install_deps(client, findings)
                else:
                    print(_red(
                        "Missing required packages: "
                        + ", ".join(missing_blockers)
                    ))
                    print("  Re-run with --install-deps to opkg install them, "
                          "or install manually first.")
                    return 1
        upload(client, args.remote)
        if not args.skip_install:
            run_install(client, args.remote)
            print()
            status_check(client)
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
