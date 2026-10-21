@echo off
setlocal
cd /d "%~dp0"
title Faultline - Local workspace
echo.
echo Faultline - Dependency intelligence
echo.
where node >nul 2>nul
if errorlevel 1 (
  echo Install Node.js 24 or later from https://nodejs.org then run this file again.
  goto :failed
)
node -e "if(Number(process.versions.node.split('.')[0])<24){console.error('Node.js 24 or later is required.');process.exit(1)}"
if errorlevel 1 goto :failed
if not exist "package.json" (
  echo The project files are missing. Extract the entire ZIP before opening start.cmd.
  goto :failed
)
if not exist "scripts\launch.mjs" (
  echo The launcher files are missing. Extract the entire updated ZIP into one folder.
  goto :failed
)
if not exist "dist\src\server.js" (
  echo Preparing this source checkout. The first run needs an internet connection.
  call npm --version >nul 2>nul
  if errorlevel 1 (
    echo npm was not found. Reinstall Node.js with npm, or use the prebuilt package.
    goto :failed
  )
  call npm ci --ignore-scripts --no-fund
  if errorlevel 1 goto :failed
  call npm run build
  if errorlevel 1 goto :failed
)
node scripts\launch.mjs
if errorlevel 1 goto :failed
exit /b 0

:failed
echo.
echo Faultline could not start. The error is shown above.
echo Keep this message when asking for help.
echo.
pause
exit /b 1
