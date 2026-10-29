@echo off
REM Xaxglog dev launcher for Windows. Installs React deps on first run.
setlocal
cd /d "%~dp0"

where python >nul 2>nul || (echo missing python & exit /b 1)
where npm >nul 2>nul || (echo missing npm & exit /b 1)

if not exist "frontend\node_modules\.bin\react-scripts.cmd" (
  echo [xaxglog] installing React dependencies...
  pushd frontend
  if exist package-lock.json (call npm ci --no-audit --no-fund) else (call npm install --no-audit --no-fund)
  popd
)

start "Xaxglog backend" cmd /k "cd /d %~dp0backend && python app.py"
start "Xaxglog React" cmd /k "cd /d %~dp0frontend && set BROWSER=none&& npm start"
echo backend: http://127.0.0.1:5000/
echo React:   http://localhost:3000/
endlocal
