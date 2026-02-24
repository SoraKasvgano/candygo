#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${ROOT_DIR}/dist"

mkdir -p "${DIST_DIR}"

if ! command -v go >/dev/null 2>&1; then
  echo "[ERROR] go command not found in PATH." >&2
  exit 1
fi

build_target() {
  local goos="$1"
  local goarch="$2"
  local goarm="$3"
  local gomips="$4"
  local output_name="$5"

  local -a env_vars
  env_vars=("CGO_ENABLED=0" "GOOS=${goos}" "GOARCH=${goarch}")
  if [[ -n "${goarm}" ]]; then
    env_vars+=("GOARM=${goarm}")
  fi
  if [[ -n "${gomips}" ]]; then
    env_vars+=("GOMIPS=${gomips}")
  fi

  echo "[INFO] Building ${output_name} (GOOS=${goos}, GOARCH=${goarch})"
  env "${env_vars[@]}" go build -o "${DIST_DIR}/${output_name}" .
}

build_target windows amd64 "" "" candygo-windows-amd64.exe
build_target linux amd64 "" "" candygo-linux-amd64
build_target linux arm 7 "" candygo-linux-armv7
build_target linux arm64 "" "" candygo-linux-armv8
build_target linux mips "" softfloat candygo-linux-mips
build_target linux mipsle "" softfloat candygo-linux-mipsel

echo "[INFO] Build completed successfully."
echo "[INFO] Output files:"
ls -1 "${DIST_DIR}"/candygo-*
