@echo off
setlocal EnableExtensions

set "ROOT=%~dp0"
pushd "%ROOT%" >nul 2>&1 || (
  echo [ERROR] Failed to enter project directory: "%ROOT%"
  exit /b 1
)

set "DIST=%ROOT%dist"
if not exist "%DIST%" (
  mkdir "%DIST%" || (
    echo [ERROR] Failed to create dist directory: "%DIST%"
    popd
    exit /b 1
  )
)

where go >nul 2>&1 || (
  echo [ERROR] "go" was not found in PATH.
  popd
  exit /b 1
)

call :build windows amd64 "" "" candygo-windows-amd64.exe || goto :failed
call :build linux amd64 "" "" candygo-linux-amd64 || goto :failed
call :build linux arm 7 "" candygo-linux-armv7 || goto :failed
call :build linux arm64 "" "" candygo-linux-armv8 || goto :failed
call :build linux mips "" softfloat candygo-linux-mips || goto :failed
call :build linux mipsle "" softfloat candygo-linux-mipsel || goto :failed

echo [INFO] Build completed successfully.
echo [INFO] Output files:
dir /b "%DIST%\candygo-*"
popd
exit /b 0

:build
setlocal
set "GOOS=%~1"
set "GOARCH=%~2"
set "GOARM=%~3"
set "GOMIPS=%~4"
set "OUTNAME=%~5"
set "CGO_ENABLED=0"

echo [INFO] Building %OUTNAME% ^(GOOS=%GOOS%, GOARCH=%GOARCH%^)
go build -o "%DIST%\%OUTNAME%" .
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%

:failed
echo [ERROR] Build failed.
popd
exit /b 1
