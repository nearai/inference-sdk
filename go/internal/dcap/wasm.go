//go:build !dcap_native

package dcap

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed dcap.wasm
var verifierWASM []byte

// Cache compiled code, never guest memory or verification evidence. Every call
// receives an isolated instance with no filesystem or network access.
var verifierCache = wazero.NewCompilationCache()

type wasmRequest struct {
	Operation  string             `json:"operation"`
	Input      string             `json:"input"`
	Collateral *QuoteCollateralV3 `json:"collateral,omitempty"`
	Now        uint64             `json:"now"`
	Root       string             `json:"root,omitempty"`
}

func wasmCall(ctx context.Context, request wasmRequest, result any) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}

	input, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if len(input) > 16<<20 {
		return fmt.Errorf("dcap: input exceeds verifier limit")
	}

	config := wazero.NewRuntimeConfig().WithCompilationCache(verifierCache).
		WithMemoryLimitPages(2048).WithCloseOnContextDone(true)
	runtime := wazero.NewRuntimeWithConfig(ctx, config)
	defer runtime.Close(context.Background())
	if _, err = wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		return err
	}

	var output bytes.Buffer
	moduleConfig := wazero.NewModuleConfig().WithName("").
		WithStdin(bytes.NewReader(input)).WithStdout(&output)
	if _, err = runtime.InstantiateWithConfig(ctx, verifierWASM, moduleConfig); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("dcap: verifier execution failed: %w", err)
	}
	var response struct {
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err = json.Unmarshal(output.Bytes(), &response); err != nil {
		return fmt.Errorf("dcap: invalid verifier output: %w", err)
	}
	if response.Error != "" {
		return fmt.Errorf("dcap: %s", response.Error)
	}
	if len(response.Result) == 0 {
		return fmt.Errorf("dcap: missing verifier result")
	}
	return json.Unmarshal(response.Result, result)
}

func ParseQuote(raw []byte) (*Quote, error) {
	return ParseQuoteContext(context.Background(), raw)
}

func ParseQuoteContext(ctx context.Context, raw []byte) (*Quote, error) {
	var result Quote
	err := wasmCall(ctx, wasmRequest{Operation: "parse", Input: hex.EncodeToString(raw)}, &result)
	return &result, err
}

func Verify(raw []byte, collateral *QuoteCollateralV3, now uint64) (*VerifiedReport, error) {
	return VerifyContext(context.Background(), raw, collateral, now)
}

func VerifyContext(ctx context.Context, raw []byte, collateral *QuoteCollateralV3, now uint64) (*VerifiedReport, error) {
	var result VerifiedReport
	err := wasmCall(ctx, wasmRequest{Operation: "verify", Input: hex.EncodeToString(raw), Collateral: collateral, Now: now}, &result)
	return &result, err
}

func VerifyWithRootCA(raw []byte, collateral *QuoteCollateralV3, root []byte, now uint64) (*VerifiedReport, error) {
	if len(root) == 0 {
		return nil, fmt.Errorf("dcap: empty root CA input")
	}
	var result VerifiedReport
	err := wasmCall(context.Background(), wasmRequest{
		Operation:  "verify",
		Input:      hex.EncodeToString(raw),
		Collateral: collateral,
		Now:        now,
		Root:       hex.EncodeToString(root),
	}, &result)
	return &result, err
}

func ParsePCKExtensionFromPEM(raw []byte) (*PCKExtension, error) {
	var result PCKExtension
	err := wasmCall(context.Background(), wasmRequest{Operation: "pck", Input: hex.EncodeToString(raw)}, &result)
	return &result, err
}
