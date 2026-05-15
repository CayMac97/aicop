@echo off
title VibeCop Installer
echo.
echo  =========================================
echo   VibeCop - AI Code Scanner
echo   Installing via npm...
echo  =========================================
echo.

where node >nul 2>nul
if %errorlevel% neq 0 (
    echo  [ERROR] Node.js is not installed.
    echo  Please install Node.js first: https://nodejs.org
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('node -v') do set NODE_VER=%%i
echo  Node.js found: %NODE_VER%
echo.
echo  Installing vibecop globally...
echo.

call npm install -g vibecop

if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Installation failed.
    echo  Try running this script as Administrator.
    pause
    exit /b 1
)

echo.
echo  =========================================
echo   VibeCop installed successfully!
echo.
echo   Usage:
echo     cd your-project
echo     vibecop scan ./src
echo  =========================================
echo.
pause
