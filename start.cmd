@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Install Node.js 24 or later from https://nodejs.org then run this file again.
  pause
  exit /b 1
)
node -e "if(Number(process.versions.node.split('.')[0])<24){console.error('Node.js 24 or later is required.');process.exit(1)}"
if errorlevel 1 exit /b 1
if not exist "dist\src\server.js" (
  call npm ci --ignore-scripts --no-fund
  if errorlevel 1 exit /b 1
  call npm run build
  if errorlevel 1 exit /b 1
)
echo Open http://127.0.0.1:4317 in your browser. Press Ctrl+C to stop.
node dist\src\server.js
