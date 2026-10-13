# Embedded DCAP verifier

The default backend executes DCAP QVL locally as embedded WebAssembly using
[wazero](https://github.com/tetratelabs/wazero). Consumers need only Go:
`go get` includes the artifact, and `CGO_ENABLED=0` builds work without Rust,
a C compiler, native libraries, linker flags, or runtime downloads.

The artifact uses [DCAP QVL 0.6.5, revision
884e22ce767f31fd5d5a6672511519fc7975cde0](https://github.com/Phala-Network/dcap-qvl/tree/884e22ce767f31fd5d5a6672511519fc7975cde0)
with the RustCrypto backend and Intel production root. The wrapper and flattened
JSON serialization live in `wasm-src/`; the serialization is adapted from that
revision's MIT-licensed FFI, under the accompanying upstream LICENSE. No quote
verification checks are disabled. Collateral retrieval stays in Go, with context
cancellation, bounded responses, redirect rejection, and restricted Intel CRL URLs.

Each operation uses isolated guest memory with no filesystem or network access.
Compiled code is cached, but evidence and guest instances are not. Calls have a
128 MiB guest memory limit, 16 MiB input limit, and two-minute execution deadline;
quote verification also honors caller cancellation. WASM executes within the Go
process; it is not a remote verification service.

## Maintainer rebuild

Consumers never need this step. The canonical artifact builder is macOS arm64
with Rust 1.99.0; use that environment to update the committed artifact:

```sh
rustup toolchain install 1.99.0 --profile minimal --component rustfmt --target wasm32-wasip1
RUSTUP_TOOLCHAIN=1.99.0 ./go/scripts/build-dcap-wasm.sh
cargo fmt --manifest-path go/internal/dcap/wasm-src/Cargo.toml --check
CGO_ENABLED=0 go -C go test ./...
```

The source revision, wrapper dependencies, Rust toolchain, and release settings
are pinned. CI rebuilds on the canonical macOS arm64 host and compares the
artifact byte for byte. Builds on other host toolchains can differ in bytes;
Linux and macOS consumer tests verify the same committed artifact. Review all
source and lockfile changes when upgrading; include signed-quote, tampering,
expired-collateral, cancellation, and live E2E checks.

An optional `dcap_native` build tag retains the previous CGO backend for
maintainer comparisons. It requires the static library from
`go/scripts/build-dcap.sh` and its `CGO_LDFLAGS`; it is not the default consumer
installation path. Its binding comes from upstream revision
364f78c2715167680be7e4a9ec6a482b8577027f and retains the synchronous `cgo.Handle`
callback fix needed by race/checkptr instrumentation.

## Local comparison

With stripped builds of the same OpenAI example on macOS arm64, the embedded
backend produced a 28.6 MB executable versus 24.6 MB for native DCAP (decimal MB).
The embedded artifact itself is about 620 KiB. A ten-iteration offline signed-quote
benchmark measured about 109 ms per verification versus 0.7 ms for native DCAP;
the embedded backend allocated about 23.5 MB per operation, not retained heap.
These are local measurements, not cross-platform performance guarantees.
Deployment verification is normally cached for one hour by the integrated client.
Run `go test ./internal/dcap -run '^$' -bench BenchmarkOfflineTDXVerification`
to measure your environment; use the optional native tag for comparison.
