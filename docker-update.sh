#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

CONTAINER_NAME="${CONTAINER_NAME:-candygo}"
IMAGE_NAME="${IMAGE_NAME:-candygo:latest}"
DOCKERFILE_PATH="${DOCKERFILE_PATH:-dockerfile}"

DEFAULT_CMD=("-c" "/etc/candy.cfg")
DEFAULT_NETWORK_MODE="host"
DEFAULT_RESTART_POLICY="unless-stopped"
DEFAULT_PRIVILEGED="true"
DEFAULT_BINDS=(
  "/var/lib/candy:/var/lib/candy"
  "${CANDY_CONFIG_BIND:-/path/to/candy.cfg:/etc/candy.cfg:ro}"
)

if ! command -v docker >/dev/null 2>&1; then
  echo "[ERROR] docker command not found in PATH." >&2
  exit 1
fi

if [[ ! -f "${DOCKERFILE_PATH}" ]]; then
  echo "[ERROR] Dockerfile not found: ${DOCKERFILE_PATH}" >&2
  exit 1
fi

if [[ ! -f "dist/candygo-linux-amd64" ]]; then
  echo "[ERROR] Missing dist/candygo-linux-amd64. Run ./build.sh or build.bat first." >&2
  exit 1
fi

cmd_args=("${DEFAULT_CMD[@]}")
network_mode="${DEFAULT_NETWORK_MODE}"
restart_policy="${DEFAULT_RESTART_POLICY}"
privileged="${DEFAULT_PRIVILEGED}"
binds=("${DEFAULT_BINDS[@]}")

if docker container inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
  echo "[INFO] Existing container found, extracting runtime parameters..."

  cmd_joined="$(docker inspect --format '{{range $i, $e := .Config.Cmd}}{{if $i}}{{print "\x1f"}}{{end}}{{print $e}}{{end}}' "${CONTAINER_NAME}")"
  if [[ -n "${cmd_joined}" ]]; then
    IFS=$'\x1f' read -r -a cmd_args <<< "${cmd_joined}"
  fi

  network_mode="$(docker inspect --format '{{.HostConfig.NetworkMode}}' "${CONTAINER_NAME}")"
  restart_policy="$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "${CONTAINER_NAME}")"
  privileged="$(docker inspect --format '{{.HostConfig.Privileged}}' "${CONTAINER_NAME}")"

  mapfile -t inspected_binds < <(docker inspect --format '{{range .HostConfig.Binds}}{{println .}}{{end}}' "${CONTAINER_NAME}")
  if [[ "${#inspected_binds[@]}" -gt 0 ]]; then
    binds=("${inspected_binds[@]}")
  fi
fi

echo "[INFO] Removing old container (if exists): ${CONTAINER_NAME}"
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

echo "[INFO] Removing old image (if exists): ${IMAGE_NAME}"
docker image rm -f "${IMAGE_NAME}" >/dev/null 2>&1 || true

echo "[INFO] Building image with native docker build (no buildx): ${IMAGE_NAME}"
docker build -f "${DOCKERFILE_PATH}" -t "${IMAGE_NAME}" .

run_args=(
  -d
  --name "${CONTAINER_NAME}"
)

if [[ -n "${network_mode}" ]]; then
  run_args+=(--network "${network_mode}")
fi
if [[ "${privileged}" == "true" ]]; then
  run_args+=(--privileged)
fi
if [[ -n "${restart_policy}" && "${restart_policy}" != "no" ]]; then
  run_args+=(--restart "${restart_policy}")
fi
for bind in "${binds[@]}"; do
  [[ -n "${bind}" ]] || continue
  run_args+=(-v "${bind}")
done

echo "[INFO] Creating new container with preserved parameters..."
docker run "${run_args[@]}" "${IMAGE_NAME}" "${cmd_args[@]}"

echo "[INFO] Update completed."
echo "[INFO] Container: ${CONTAINER_NAME}"
echo "[INFO] Image: ${IMAGE_NAME}"

