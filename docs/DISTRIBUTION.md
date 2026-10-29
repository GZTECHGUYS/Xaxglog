# Lightweight distribution

Xaxglog ships as a Python engine plus a built-in web console. The React app is
optional for development; the compiled build serves the built-in console at
`/` and exposes the same JSON API.

## Build targets

| Target | Command | Output |
|---|---|---|
| Linux one-folder | `python packaging/build.py --target pyinstaller` | `dist/Xaxglog/` |
| Debian package | `python packaging/build.py --target deb` | `dist/xaxglog_1.1.0_amd64.deb` |
| AppImage (optional) | `python packaging/build.py --target appimage` | `dist/Xaxglog-1.1.0-x86_64.AppImage` |
| Windows portable | `powershell -File packaging/build_windows.ps1` | `dist/Xaxglog/Xaxglog.exe` |
| Windows zip | `Compress-Archive dist/Xaxglog dist/Xaxglog-windows.zip` | `dist/Xaxglog-windows.zip` |

PyInstaller is not in the runtime requirements; install it only for builds:

```bash
python -m pip install pyinstaller
```

## One-folder vs one-file

Use one-folder builds. They start faster, avoid extracting to `%TEMP%`, make
module-pack replacement possible, and trigger fewer antivirus false positives.
The CI workflow produces one-folder builds on both Windows and Linux.

## Windows signing

An unsigned `.exe` is a development artifact. For production:

1. Obtain an Authenticode code-signing certificate.
2. Set the certificate thumbprint:
   ```powershell
   ./packaging/build_windows.ps1 -CertThumbprint <THUMBPRINT>
   ```
3. Verify with `signtool verify /pa /v dist/Xaxglog/Xaxglog.exe`.
4. Build an installer (Inno Setup/WiX/MSIX) around the signed one-folder tree.

Never commit a certificate or private key. The repository `.gitignore` excludes
`*.pem`, `*.key` and `.env`.

## Linux packaging notes

The `.deb` installs to `/opt/xaxglog` and exposes `/usr/bin/xaxglog` plus a
desktop entry. It does not create a systemd service by default; run it as the
operator account, or add a unit with an explicit `User=` and data directory.
Runtime data lives in `data/` next to the app or in the path configured by the
service unit. Do not run the server as root in production.

## Runtime budgets

Defaults (override with env vars):

- `XAXGLOG_BUDGET_COLD_START_MS=2500`
- `XAXGLOG_BUDGET_HEALTH_MS=250`
- `XAXGLOG_BUDGET_QUERY_MS=1500`
- `XAXGLOG_BUDGET_INSTALLER_MB=120`

Check them at `GET /api/platform/runtime` and benchmark at
`POST /api/platform/performance/benchmark`.

## Reproducibility

- Pin Python and Node versions in CI.
- Use `npm ci` (lockfile) rather than `npm install`.
- Keep PyInstaller/Nuitka versions pinned in the release workflow.
- Build from a clean tag and record the source commit in the release notes.
- The binary is not byte-for-byte reproducible across OS toolchains; treat the
  source commit plus lockfiles as the reproducible input.
