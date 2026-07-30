#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run_rust_checks() {
  local rel_dir="$1"
  echo "Linting ${rel_dir}..."
  (cd "${ROOT_DIR}/${rel_dir}" && cargo clippy)
  echo "Formatting ${rel_dir}..."
  (cd "${ROOT_DIR}/${rel_dir}" && cargo fmt)
}

run_rust_checks "code/server"
run_rust_checks "code/utils"