#!/usr/bin/env bash
set -euo pipefail
# Maintainer-only: consumers use the artifact embedded in the Go module.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
crate_dir="$script_dir/../internal/dcap/wasm-src"
build_dir="${NEARAI_DCAP_WASM_TARGET:-${TMPDIR:-/tmp}/nearai-dcap-wasm-target}"
repo_dir="$(cd "$script_dir/../.." && pwd)"
cargo_source_dir="${CARGO_HOME:-$HOME/.cargo}"
# Normalize panic/source locations so rebuilding on another host is reproducible.
export RUSTFLAGS="--remap-path-prefix=$repo_dir=/src --remap-path-prefix=$cargo_source_dir=/cargo"
export SOURCE_DATE_EPOCH=0
if [[ "$(rustc --version)" != "rustc 1.99.0 "* ]]; then
  echo 'Rebuild with Rust 1.99.0 (set RUSTUP_TOOLCHAIN=1.99.0)' >&2
  exit 1
fi
cargo build --manifest-path "$crate_dir/Cargo.toml" --locked \
  --release --target wasm32-wasip1 --target-dir "$build_dir"
cp "$build_dir/wasm32-wasip1/release/nearai-dcap-wasm.wasm" "$script_dir/../internal/dcap/dcap.wasm"
chmod 644 "$script_dir/../internal/dcap/dcap.wasm"
