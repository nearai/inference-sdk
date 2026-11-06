# NEAR AI Inference SDK for Go

`github.com/nearai/inference-sdk/go` provides Chat Completions, Responses, Messages, and System One
with deployment attestation, response signature verification, and optional encryption.

## Install

Go 1.26.10+. The SDK includes the DCAP verifier and supports `CGO_ENABLED=0`.

```sh
go get github.com/nearai/inference-sdk/go
```

## Send and verify a Chat completion

Set `NEARAI_API_KEY`, then send a request with E2EE enabled:

```sh
export NEARAI_API_KEY='your-api-key'
```

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "os"
    "time"

    nearai "github.com/nearai/inference-sdk/go"
)

func main() {
    if err := run(); err != nil {
        log.Fatal(err)
    }
}

func run() error {
    apiKey := os.Getenv("NEARAI_API_KEY")
    if apiKey == "" {
        return fmt.Errorf("set NEARAI_API_KEY")
    }
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    client, err := nearai.NewInferenceClient(nearai.InferenceOptions{
        ClientOptions: nearai.ClientOptions{APIKey: apiKey},
        E2EE: true,
    })
    if err != nil {
        return err
    }
    defer client.Close()

    body, err := client.CreateChatCompletion(ctx, map[string]any{
        "model": "z-ai/glm-5.3-flash",
        "messages": []map[string]string{{"role": "user", "content": "Hello!"}},
    })
    if err != nil {
        return err
    }
    var completion struct {
        ID string `json:"id"`
    }
    if err := json.Unmarshal(body, &completion); err != nil {
        return err
    }
    if completion.ID == "" {
        return fmt.Errorf("completion has no ID")
    }

    verified, err := client.VerifyResponse(ctx, completion.ID)
    if err != nil {
        return err
    }
    fmt.Println(verified.SignatureKind)
    fmt.Println(string(body))
    return nil
}
```

The client uses the NEAR AI Cloud Gateway by default. It verifies the Gateway and
every returned model report before inference. Call `VerifyResponse(ctx, id)` to verify
the response signature; consume streaming responses completely first.

Use `CreateChatCompletion` for JSON or `HTTPClient()` with the official OpenAI
SDK for streaming. Close the client and response bodies when finished.

## Configuration

| Feature | Default |
| --- | --- |
| Gateway and supported model attestation | Enabled |
| Signing algorithm | Ed25519; ECDSA also supported |
| E2EE for supported Chat models | Disabled; enable with `E2EE: true` |
| OHTTP for Chat, Responses, and Messages | Disabled; enable with `OHTTP: true`; requires Ed25519 |

Call `client.Verify(ctx, model)` to verify a deployment before sending a prompt.
Use deployment and image provenance policies to restrict accepted deployments.
Models without model attestation use Gateway-only verification with E2EE disabled.

## Documentation

- [Verification guide](./docs/verification-guide.md): streaming, official SDK integration,
  encryption, deployment policies, and standalone verification.
- [API reference](./docs/api-reference.md): options, methods, and result fields.
- [Runnable examples](../examples/README.md#go-setup): Gateway and Direct workflows.
- [Development checks](../TESTING.md#validation) and [live E2E tests](../e2e/README.md).
