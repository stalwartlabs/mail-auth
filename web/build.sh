#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack not found. Install it with:" >&2
  echo "  cargo install wasm-pack" >&2
  echo "  # or: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh" >&2
  exit 1
fi

OUT_DIR="dist"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

wasm-pack build --release --target web --out-dir "$OUT_DIR/pkg" --no-typescript

cp -r site/. "$OUT_DIR/"

echo "Built static site in web/$OUT_DIR"
echo "Serve locally with: python3 -m http.server --directory web/$OUT_DIR 8080"
