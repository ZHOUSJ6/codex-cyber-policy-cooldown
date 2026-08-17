#!/usr/bin/env bash
# Build the codex-cyber-policy-cooldown plugin.
# CGO is mandatory for CPA plugins, so a C compiler (gcc/clang) must be on PATH.
# Output: codex-cyber-policy-cooldown.dll (windows), .dylib (darwin), .so (linux).
set -euo pipefail

ext="so"
case "$(go env GOOS)" in
    windows) ext="dll" ;;
    darwin)  ext="dylib" ;;
esac
out="codex-cyber-policy-cooldown.${ext}"

echo "Building $out (CGO c-shared)..."
GOWORK=off CGO_ENABLED=1 go build -buildmode=c-shared -o "$out" .

echo
echo "Built: $(pwd)/$out"
echo "Next: copy it to <cpa>/plugins/$(go env GOOS)/$(go env GOARCH)/$out"
echo "      and enable it in config.yaml (see README.md)."
