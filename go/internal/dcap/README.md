# DCAP QVL adapter

The Go binding sources and header are copied from
[Phala-Network/dcap-qvl, commit 364f78c2715167680be7e4a9ec6a482b8577027f](https://github.com/Phala-Network/dcap-qvl/tree/364f78c2715167680be7e4a9ec6a482b8577027f/golang-bindings)
(`golang-bindings/v0.1.0`), under the accompanying MIT license.

Local changes:

- Pass a pointer to `cgo.Handle` through the synchronous FFI callback instead of
  converting the handle integer to a pointer. The upstream conversion crashes
  with Go's race/checkptr instrumentation.
- Propagate the caller's context through collateral HTTP requests; refuse redirects.
- Bound collateral bodies to 16 MiB and restrict certificate-supplied CRL fallback
  URLs to Intel's certificate service over HTTPS.

The cryptographic verifier remains the upstream Rust DCAP QVL core, linked
statically. See `../../scripts/build-dcap.sh` for its pinned source revision.
There is no Node.js or Python runtime dependency. Keep the C ABI and these Go
structs aligned when upgrading the native core. Run the SDK race tests and
malformed-quote tests after changing the binding.
