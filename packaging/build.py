#!/usr/bin/env python3
"""Build lightweight Xaxglog distributions.

Targets
-------
``pyinstaller``  one-folder native build (works on Windows/Linux/macOS)
``deb``          Debian package from the Linux one-folder build
``appimage``     optional AppImage wrapper (requires linuxdeploy on PATH)
``all``          native build + deb/appimage when the host supports them

The Windows portable ``.exe`` is produced by running the PyInstaller target on
Windows (CI matrix).  Code signing is an optional post-step; see
docs/DISTRIBUTION.md.  No Docker is used.
"""
from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys
import textwrap

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DIST = os.path.join(ROOT, "dist")
BUILD = os.path.join(ROOT, "build", "pyinstaller")
VERSION = os.getenv("XAXGLOG_VERSION", "1.1.0")
APP = "Xaxglog"


def run(cmd, cwd=None):
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd or ROOT, check=True)


def pyinstaller():
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        raise SystemExit("PyInstaller is required: python -m pip install pyinstaller")
    run([sys.executable, "-m", "PyInstaller", os.path.join("packaging", "xaxglog.spec"),
         "--distpath", DIST, "--workpath", BUILD, "--noconfirm"])
    out = os.path.join(DIST, APP)
    if not os.path.isdir(out):
        raise SystemExit(f"PyInstaller did not produce {out}")
    return out


def _write(path, content, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    os.chmod(path, mode)


def deb(source_dir):
    if not shutil.which("dpkg-deb"):
        print("dpkg-deb not found; skipping .deb")
        return None
    stage = os.path.join(ROOT, "build", "deb", "xaxglog")
    if os.path.isdir(stage):
        shutil.rmtree(stage)
    os.makedirs(stage)
    dest = os.path.join(stage, "opt", "xaxglog")
    shutil.copytree(source_dir, dest)
    _write(os.path.join(stage, "DEBIAN", "control"), textwrap.dedent(f"""\
        Package: xaxglog
        Version: {VERSION}
        Section: utils
        Priority: optional
        Architecture: amd64
        Maintainer: Xaxglog <maintainers@example.invalid>
        Description: Lightweight public-source OSINT intelligence platform
         Xaxglog combines a verified public-source registry, evidence graph,
         social/human recon, module packs, offline mode and an operator console.
         Public/free sources only; no login-wall bypass or private databases.
        """))
    _write(os.path.join(stage, "usr", "bin", "xaxglog"),
           "#!/bin/sh\nexec /opt/xaxglog/Xaxglog \"$@\"\n", 0o755)
    _write(os.path.join(stage, "usr", "share", "applications", "xaxglog.desktop"),
           textwrap.dedent("""\
           [Desktop Entry]
           Type=Application
           Name=Xaxglog
           Comment=Public-source OSINT intelligence platform
           Exec=xaxglog
           Terminal=true
           Categories=Utility;Security;
           """))
    out = os.path.join(DIST, f"xaxglog_{VERSION}_amd64.deb")
    run(["dpkg-deb", "--build", stage, out])
    return out


def appimage(source_dir):
    linuxdeploy = shutil.which("linuxdeploy") or shutil.which("linuxdeploy-x86_64.AppImage")
    if not linuxdeploy:
        print("linuxdeploy not found; skipping AppImage (optional)")
        return None
    appdir = os.path.join(ROOT, "build", "AppDir")
    if os.path.isdir(appdir):
        shutil.rmtree(appdir)
    shutil.copytree(source_dir, os.path.join(appdir, "usr", "bin"))
    _write(os.path.join(appdir, "AppRun"), "#!/bin/sh\nexec \"$APPDIR/usr/bin/Xaxglog\" \"$@\"\n", 0o755)
    _write(os.path.join(appdir, "xaxglog.desktop"), textwrap.dedent("""\
        [Desktop Entry]
        Type=Application
        Name=Xaxglog
        Exec=Xaxglog
        Terminal=true
        Categories=Utility;Security;
        """))
    out = os.path.join(DIST, f"Xaxglog-{VERSION}-x86_64.AppImage")
    run([linuxdeploy, "--appdir", appdir, "--output", "appimage"], cwd=DIST)
    produced = [f for f in os.listdir(DIST) if f.endswith(".AppImage")]
    if produced:
        newest = max((os.path.join(DIST, f) for f in produced), key=os.path.getmtime)
        if newest != out:
            shutil.move(newest, out)
        return out
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["pyinstaller", "deb", "appimage", "all"], default="all")
    args = parser.parse_args()
    os.makedirs(DIST, exist_ok=True)
    source = pyinstaller()
    print("native build:", source)
    if args.target in ("deb", "all"):
        print("deb:", deb(source))
    if args.target in ("appimage", "all"):
        print("appimage:", appimage(source))


if __name__ == "__main__":
    main()
