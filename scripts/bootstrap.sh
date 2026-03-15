#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
EXECUTABLE="${BUILD_DIR}/fileguard"

SCAN_PATH="${ROOT_DIR}"
THREADS="$(nproc 2>/dev/null || echo 4)"
JSON_OUT="${BUILD_DIR}/report.json"
MAX_SIZE_MB=""
FOLLOW_SYMLINKS=0
INSTALL_DEPS=1

usage() {
  cat <<'EOF'
Usage: ./scripts/bootstrap.sh [options]

Options:
  --path <dir>            Directory to scan (default: project root)
  --threads <N>           Number of worker threads (default: nproc or 4)
  --json <file>           JSON output path (default: build/report.json)
  --max-size <MB>         Skip files larger than MB
  --follow-symlinks       Follow symlinks during recursive scan
  --no-install            Skip dependency installation step
  -h, --help              Show this help message
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

install_deps_debian() {
  echo "[1/3] Installing dependencies (Debian/Ubuntu)..."
  require_cmd sudo
  sudo apt update
  sudo apt install -y cmake g++ build-essential pkg-config libssl-dev
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --path)
        [[ $# -ge 2 ]] || { echo "Missing value for --path" >&2; exit 1; }
        SCAN_PATH="$2"
        shift 2
        ;;
      --threads)
        [[ $# -ge 2 ]] || { echo "Missing value for --threads" >&2; exit 1; }
        THREADS="$2"
        shift 2
        ;;
      --json)
        [[ $# -ge 2 ]] || { echo "Missing value for --json" >&2; exit 1; }
        JSON_OUT="$2"
        shift 2
        ;;
      --max-size)
        [[ $# -ge 2 ]] || { echo "Missing value for --max-size" >&2; exit 1; }
        MAX_SIZE_MB="$2"
        shift 2
        ;;
      --follow-symlinks)
        FOLLOW_SYMLINKS=1
        shift
        ;;
      --no-install)
        INSTALL_DEPS=0
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown argument: $1" >&2
        usage
        exit 1
        ;;
    esac
  done
}

main() {
  parse_args "$@"

  if [[ "${INSTALL_DEPS}" -eq 1 ]]; then
    if command -v apt >/dev/null 2>&1; then
      install_deps_debian
    else
      echo "Auto-install is implemented for apt-based systems only." >&2
      echo "Install manually: cmake, g++, build-essential, pkg-config, libssl-dev" >&2
      exit 1
    fi
  fi

  echo "[2/3] Configuring and building project..."
  require_cmd cmake
  cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}"
  cmake --build "${BUILD_DIR}" -j

  if [[ ! -x "${EXECUTABLE}" ]]; then
    echo "Build completed but executable not found at ${EXECUTABLE}" >&2
    exit 1
  fi

  mkdir -p "$(dirname "${JSON_OUT}")"

  echo "[3/3] Running scan..."
  run_args=(--path "${SCAN_PATH}" --threads "${THREADS}" --json "${JSON_OUT}")

  if [[ -n "${MAX_SIZE_MB}" ]]; then
    run_args+=(--max-size "${MAX_SIZE_MB}")
  fi
  if [[ "${FOLLOW_SYMLINKS}" -eq 1 ]]; then
    run_args+=(--follow-symlinks)
  fi

  "${EXECUTABLE}" "${run_args[@]}"

  echo "Done. JSON report: ${JSON_OUT}"
}

main "$@"
