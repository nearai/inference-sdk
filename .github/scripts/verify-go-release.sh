#!/usr/bin/env bash
set -euo pipefail

: "${RELEASE_VERSION:?}"
: "${GITHUB_SHA:?}"

# A new tag can take time to reach the public proxy. Never fall back to a local
# replacement or a direct VCS download: consumers must be able to install it.
export GOPROXY=https://proxy.golang.org
export GOSUMDB=sum.golang.org
export GOWORK=off
export CGO_ENABLED=0
module=github.com/nearai/inference-sdk/go
consumer=$(mktemp -d)
trap 'rm -rf "$consumer"' EXIT
cd "$consumer"
go mod init example.com/nearai-release-check

available=false
for attempt in 1 2 3 4 5 6; do
  if go list -m -json "$module@v$RELEASE_VERSION" > module.json; then
    available=true
    break
  fi
  if [ "$attempt" -lt 6 ]; then
    sleep 10
  fi
done
if [ "$available" != true ]; then
  printf 'Go release did not become available from the public proxy.\n' >&2
  exit 1
fi

python3 - <<'PY'
import json
import os

with open("module.json", encoding="utf-8") as source:
    module = json.load(source)
expected = "v" + os.environ["RELEASE_VERSION"]
if module.get("Version") != expected:
    raise SystemExit("Public proxy returned a different version.")
if module.get("Origin", {}).get("Hash") != os.environ["GITHUB_SHA"]:
    raise SystemExit("Public proxy returned a different source commit.")
PY

go get "$module@v$RELEASE_VERSION"
cat > main.go <<'GO'
package main

import (
    "context"
    "errors"
    "fmt"

    nearai "github.com/nearai/inference-sdk/go"
)

func main() {
    client, err := nearai.NewInferenceClient(nearai.InferenceOptions{})
    if err != nil {
        panic(err)
    }
    defer client.Close()

    // Exercise the shipped WASM artifact without external collateral or API keys.
    _, err = nearai.CreateTDXQuoteVerifier("")(context.Background(), "ff")
    var sdkErr *nearai.Error
    if !errors.As(err, &sdkErr) || sdkErr.Code != "quote.verification_failed" {
        panic(fmt.Sprintf("unexpected malformed-quote result: %v", err))
    }
    fmt.Println("Published Go SDK client and embedded verifier work without CGO")
}
GO
go mod tidy
go mod verify
go run .
