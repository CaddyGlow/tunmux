#!/usr/bin/env bash
set -euo pipefail

echo "[ci] Running format check"
cargo fmt --all --check

echo "[ci] Running clippy"
cargo clippy --locked --all-targets --all-features -- -D warnings

echo "[ci] Running tests"
cargo test --locked

echo "[ci] All checks passed"
