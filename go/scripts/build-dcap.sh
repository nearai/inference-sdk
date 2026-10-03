#!/usr/bin/env bash
set -euo pipefail
# Print only the library directory to stdout so callers can capture it safely.
# Source and build artifacts live outside the module and are never published.
dcap_revision='884e22ce767f31fd5d5a6672511519fc7975cde0'
dcap_cache="${NEARAI_DCAP_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/nearai-dcap-qvl}"
dcap_source="$dcap_cache/$dcap_revision"
if [ ! -d "$dcap_source/.git" ]; then
  mkdir -p "$dcap_cache"
  git init "$dcap_source" >&2
  git -C "$dcap_source" remote add origin https://github.com/Phala-Network/dcap-qvl.git
  git -C "$dcap_source" fetch --depth 1 origin "$dcap_revision" >&2
  git -C "$dcap_source" checkout --detach FETCH_HEAD >&2
fi
if [ "$(git -C "$dcap_source" rev-parse HEAD)" != "$dcap_revision" ]; then
  echo 'DCAP source revision does not match the pinned revision' >&2
  exit 1
fi
if [ -n "$(git -C "$dcap_source" status --porcelain --untracked-files=no)" ]; then
  echo 'DCAP source checkout has modifications' >&2
  exit 1
fi
cargo build --manifest-path "$dcap_source/Cargo.toml" --locked --release --features go --target-dir "$dcap_source/target" >&2
printf '%s\n' "$dcap_source/target/release"
