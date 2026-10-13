//go:build dcap_native

package dcap

/*
#cgo linux,amd64  LDFLAGS: -Wl,-Bstatic -ldcap_qvl -Wl,-Bdynamic -lm -ldl -lpthread
#cgo linux,arm64  LDFLAGS: -Wl,-Bstatic -ldcap_qvl -Wl,-Bdynamic -lm -ldl -lpthread
#cgo darwin,amd64 LDFLAGS: -ldcap_qvl
#cgo darwin,arm64 LDFLAGS: -ldcap_qvl
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation -framework SystemConfiguration
#include "dcap_qvl.h"

extern int goDcapOutputCallback(uint8_t* data, size_t len, void* user_data);
*/
import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/cgo"
	"unsafe"
)

type ffiCallbackCtx struct {
	data   []byte
	called bool
}

//export goDcapOutputCallback
func goDcapOutputCallback(data *C.uint8_t, length C.size_t, userData unsafe.Pointer) C.int {
	h := *(*cgo.Handle)(userData)
	ctx, ok := h.Value().(*ffiCallbackCtx)
	if !ok {
		return 1
	}
	ctx.called = true
	if data == nil {
		ctx.data = nil
		return 0
	}
	ctx.data = C.GoBytes(unsafe.Pointer(data), C.int(length))
	return 0
}

func ffiCall(invoke func(C.dcap_output_cb, unsafe.Pointer) C.int) ([]byte, error) {
	ctx := &ffiCallbackCtx{}
	h := cgo.NewHandle(ctx)
	defer h.Delete()

	rc := invoke((C.dcap_output_cb)(C.goDcapOutputCallback), unsafe.Pointer(&h))
	if !ctx.called {
		return nil, fmt.Errorf("dcap ffi: callback not invoked")
	}
	if rc != 0 {
		return nil, fmt.Errorf("dcap ffi: %s", string(ctx.data))
	}
	return ctx.data, nil
}

// ParseQuote parses a raw SGX/TDX quote binary.
func ParseQuote(rawQuote []byte) (*Quote, error) {
	if len(rawQuote) == 0 {
		return nil, fmt.Errorf("dcap: empty quote input")
	}

	data, err := ffiCall(func(cb C.dcap_output_cb, userData unsafe.Pointer) C.int {
		return C.dcap_parse_quote_cb(
			(*C.uint8_t)(unsafe.Pointer(&rawQuote[0])),
			C.size_t(len(rawQuote)),
			cb,
			userData,
		)
	})
	if err != nil {
		return nil, err
	}

	var quote Quote
	if err := json.Unmarshal(data, &quote); err != nil {
		return nil, fmt.Errorf("dcap: failed to unmarshal quote JSON: %w", err)
	}
	return &quote, nil
}

// Verify verifies a quote against collateral using Intel's production root CA.
func Verify(rawQuote []byte, collateral *QuoteCollateralV3, nowSecs uint64) (*VerifiedReport, error) {
	if len(rawQuote) == 0 {
		return nil, fmt.Errorf("dcap: empty quote input")
	}

	collJSON, err := json.Marshal(collateral)
	if err != nil {
		return nil, fmt.Errorf("dcap: failed to marshal collateral: %w", err)
	}

	data, err := ffiCall(func(cb C.dcap_output_cb, userData unsafe.Pointer) C.int {
		return C.dcap_verify_cb(
			(*C.uint8_t)(unsafe.Pointer(&rawQuote[0])),
			C.size_t(len(rawQuote)),
			(*C.uint8_t)(unsafe.Pointer(&collJSON[0])),
			C.size_t(len(collJSON)),
			C.uint64_t(nowSecs),
			cb,
			userData,
		)
	})
	if err != nil {
		return nil, err
	}

	var report VerifiedReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("dcap: failed to unmarshal verify result: %w", err)
	}
	return &report, nil
}

// VerifyWithRootCA verifies a quote with a custom root CA (DER-encoded).
func VerifyWithRootCA(rawQuote []byte, collateral *QuoteCollateralV3, rootCADer []byte, nowSecs uint64) (*VerifiedReport, error) {
	if len(rawQuote) == 0 {
		return nil, fmt.Errorf("dcap: empty quote input")
	}
	if len(rootCADer) == 0 {
		return nil, fmt.Errorf("dcap: empty root CA input")
	}

	collJSON, err := json.Marshal(collateral)
	if err != nil {
		return nil, fmt.Errorf("dcap: failed to marshal collateral: %w", err)
	}

	data, err := ffiCall(func(cb C.dcap_output_cb, userData unsafe.Pointer) C.int {
		return C.dcap_verify_with_root_ca_cb(
			(*C.uint8_t)(unsafe.Pointer(&rawQuote[0])),
			C.size_t(len(rawQuote)),
			(*C.uint8_t)(unsafe.Pointer(&collJSON[0])),
			C.size_t(len(collJSON)),
			(*C.uint8_t)(unsafe.Pointer(&rootCADer[0])),
			C.size_t(len(rootCADer)),
			C.uint64_t(nowSecs),
			cb,
			userData,
		)
	})
	if err != nil {
		return nil, err
	}

	var report VerifiedReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("dcap: failed to unmarshal verify result: %w", err)
	}
	return &report, nil
}

// ParsePCKExtensionFromPEM parses Intel SGX extension from a PEM certificate chain.
func ParsePCKExtensionFromPEM(pemBytes []byte) (*PCKExtension, error) {
	if len(pemBytes) == 0 {
		return nil, fmt.Errorf("dcap: empty PEM input")
	}

	data, err := ffiCall(func(cb C.dcap_output_cb, userData unsafe.Pointer) C.int {
		return C.dcap_parse_pck_extension_from_pem_cb(
			(*C.uint8_t)(unsafe.Pointer(&pemBytes[0])),
			C.size_t(len(pemBytes)),
			cb,
			userData,
		)
	})
	if err != nil {
		return nil, err
	}

	var ext PCKExtension
	if err := json.Unmarshal(data, &ext); err != nil {
		return nil, fmt.Errorf("dcap: failed to unmarshal PCK extension: %w", err)
	}
	return &ext, nil
}

func VerifyContext(ctx context.Context, raw []byte, collateral *QuoteCollateralV3, now uint64) (*VerifiedReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := Verify(raw, collateral, now)
	if err == nil {
		err = ctx.Err()
	}
	return result, err
}
func ParseQuoteContext(ctx context.Context, raw []byte) (*Quote, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ParseQuote(raw)
}
