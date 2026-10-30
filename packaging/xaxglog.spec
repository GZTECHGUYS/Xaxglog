# PyInstaller one-folder build for the lightweight Xaxglog engine.
# One-folder is intentional: faster cold start, fewer AV false positives and
# easier module-pack replacement than one-file extraction.
import os
import sys
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
BACKEND = os.path.join(ROOT, "backend")
sys.path.insert(0, BACKEND)

hiddenimports = collect_submodules("modules", on_error="ignore")
hiddenimports += collect_submodules("routes", on_error="ignore")
datas = [
    (os.path.join(BACKEND, "templates"), "templates"),
    (os.path.join(BACKEND, "tui"), "tui"),
    (os.path.join(ROOT, "catalog"), "catalog"),
]
datas += collect_data_files("modules")

a = Analysis(
    [os.path.join(BACKEND, "app.py")],
    pathex=[BACKEND],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "notebook", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Xaxglog",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="Xaxglog",
)
