@echo off
setlocal

set "BASE=%~dp0"
set "EXE=%BASE%candygo.exe"
set "CFG=%BASE%candy.cfg"
set "WINTUN_DLL=%BASE%wintun.dll"

:: Windows client mode needs admin privilege for TUN adapter operations.
net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo [INFO] Requesting administrator privileges...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%*'"
  exit /b 0
)

if not exist "%EXE%" (
  echo [ERROR] Missing executable: "%EXE%"
  echo Build first with: go build -o candygo.exe .
  exit /b 1
)

if not exist "%WINTUN_DLL%" (
  echo [WARN] Missing "%WINTUN_DLL%".
  echo [WARN] On Windows client mode, place amd64 wintun.dll next to candygo.exe.
)

if exist "%CFG%" (
  "%EXE%" -c "%CFG%" %*
) else (
  "%EXE%" %*
)

endlocal
