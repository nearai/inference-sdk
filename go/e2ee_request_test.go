package nearai

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Paths are the public wire-field contract, independent of the SDK traversal.
func wireField(t *testing.T, body map[string]any, path string) (map[string]any, string) {
	t.Helper()
	parts := strings.Split(path, ".")
	var current any = body
	for _, part := range parts[:len(parts)-1] {
		if items, ok := current.([]any); ok {
			index, err := strconv.Atoi(part)
			if err != nil || index >= len(items) {
				t.Fatalf("invalid fixture path %s", path)
			}
			current = items[index]
		} else {
			current = current.(map[string]any)[part]
		}
	}
	return current.(map[string]any), parts[len(parts)-1]
}

func TestE2EEChatFieldContract(t *testing.T) {
	const input = `{"model":"model","messages":[{"role":"assistant","content":[{"type":"text","text":"私密问题"}],"reasoning":"reason","reasoning_content":"thought","name":"helper","refusal":"refused","audio":{"data":"audio-bytes","format":"wav"},"tool_calls":[{"id":"call-1","function":{"name":"search","arguments":"{}"}}],"function_call":{"name":"legacy","arguments":"{}"}}],"tools":[{"type":"function","function":{"name":"search","description":"lookup","parameters":{}}}],"tool_choice":{"type":"function","function":{"name":"search"}},"function_call":{"name":"legacy"},"future_option":{"enabled":true}}`
	requestFields := map[string]string{
		"messages.0.content":   `[{"text":"私密问题","type":"text"}]`,
		"messages.0.reasoning": "reason", "messages.0.reasoning_content": "thought",
		"messages.0.name": "helper", "messages.0.refusal": "refused", "messages.0.audio.data": "audio-bytes",
		"messages.0.tool_calls.0.function.name": "search", "messages.0.tool_calls.0.function.arguments": "{}",
		"messages.0.function_call.name": "legacy", "messages.0.function_call.arguments": "{}",
		"tools.0.function.name": "search", "tools.0.function.description": "lookup", "tools.0.function.parameters": "{}",
		"tool_choice.function.name": "search", "function_call.name": "legacy",
	}
	for _, algo := range []SigningAlgo{Ed25519, ECDSA} {
		t.Run(string(algo), func(t *testing.T) {
			modelKey, err := newE2EEKey(algo)
			if err != nil {
				t.Fatal(err)
			}
			request, _ := http.NewRequest("POST", "https://gateway.test/v1/chat/completions", strings.NewReader(input))
			request.Header.Set("Authorization", "Bearer caller")
			request.Header.Set("Content-Digest", "stale")
			request.Header.Set("X-Encryption-Version", "stale")
			prepared, err := PrepareE2EEChatRequest(request, E2EEModelKey{algo, modelKey.public})
			if err != nil {
				t.Fatal(err)
			}
			otherRequest, _ := http.NewRequest("POST", request.URL.String(), strings.NewReader(input))
			otherPrepared, err := PrepareE2EEChatRequest(otherRequest, E2EEModelKey{algo, modelKey.public})
			if err != nil {
				t.Fatal(err)
			}
			if prepared.Request.Header.Get("X-Client-Pub-Key") == otherPrepared.Request.Header.Get("X-Client-Pub-Key") {
				t.Fatal("requests reused a response decryption key")
			}
			wire, err := io.ReadAll(prepared.Request.Body)
			if err != nil {
				t.Fatal(err)
			}
			var encrypted, restored map[string]any
			if err := json.Unmarshal(wire, &encrypted); err != nil {
				t.Fatal(err)
			}
			aad, err := requestAAD(algo, prepared.Request.Header.Get("X-Client-Pub-Key"))
			if err != nil {
				t.Fatal(err)
			}
			for path, expected := range requestFields {
				parent, field := wireField(t, encrypted, path)
				ciphertext, ok := parent[field].(string)
				if !ok || ciphertext == expected {
					t.Fatalf("%s was not encrypted", path)
				}
				plain, err := decryptTextWithAAD(ciphertext, modelKey, fieldAAD(aad, strings.ReplaceAll(path, ".0", "[]")))
				if err != nil || plain != expected {
					t.Fatalf("%s: %q, %v", path, plain, err)
				}
				parent[field] = plain
				if path == "messages.0.content" || path == "tools.0.function.parameters" {
					var value any
					if err := json.Unmarshal([]byte(plain), &value); err != nil {
						t.Fatal(err)
					}
					parent[field] = value
				}
			}
			if err := json.Unmarshal([]byte(input), &restored); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(encrypted, restored) {
				t.Fatal("non-encrypted fields or structured content changed")
			}
			headers := prepared.Request.Header
			if headers.Get("Authorization") != "Bearer caller" || headers.Get("Content-Digest") != "" || headers.Get("X-Signing-Algo") != string(algo) || headers.Get("X-Model-Pub-Key") != modelKey.public || headers.Get("X-Client-Pub-Key") == "" || headers.Get("X-Encrypt-All-Fields") != "true" || prepared.Request.ContentLength != int64(len(wire)) {
				t.Fatal("prepared request has stale framing or wrong encryption headers")
			}
			if headers.Get("X-Encryption-Version") != "3" {
				t.Fatal("incorrect encryption version")
			}

			for _, stream := range []bool{false, true} {
				t.Run(map[bool]string{false: "json", true: "sse"}[stream], func(t *testing.T) {
					field := "message"
					if stream {
						field = "delta"
					}
					plain := `{"id":"completion","choices":[{"FIELD":{"content":"answer","reasoning":"reason","reasoning_content":"thought","refusal":"no","audio":{"data":"audio","format":"wav"},"tool_calls":[{"id":"call-1","function":{"name":"search","arguments":"{}"}}],"function_call":{"name":"legacy","arguments":"{}"}},"logprobs":{"content":[{"token":"a","bytes":[97],"top_logprobs":[{"token":"b","bytes":[98]}]}]}},{"FIELD":{"content":[{"type":"text","text":"part"}]}}],"future_option":true}`
					plain = strings.ReplaceAll(plain, "FIELD", field)
					var expected, payload map[string]any
					if err := json.Unmarshal([]byte(plain), &expected); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal([]byte(plain), &payload); err != nil {
						t.Fatal(err)
					}
					paths := []string{"choices.0.FIELD.content", "choices.0.FIELD.reasoning", "choices.0.FIELD.reasoning_content", "choices.0.FIELD.refusal", "choices.0.FIELD.audio.data", "choices.0.FIELD.tool_calls.0.function.name", "choices.0.FIELD.tool_calls.0.function.arguments", "choices.0.FIELD.function_call.name", "choices.0.FIELD.function_call.arguments", "choices.1.FIELD.content.0.text", "choices.0.logprobs.content.0.token", "choices.0.logprobs.content.0.bytes", "choices.0.logprobs.content.0.top_logprobs.0.token", "choices.0.logprobs.content.0.top_logprobs.0.bytes"}
					if stream {
						for _, obj := range []map[string]any{expected, payload} {
							parent, _ := wireField(t, obj, "choices.0.delta.content")
							parent["nearai_tool_result"] = map[string]any{"output": "tool output"}
						}
						paths = append(paths, "choices.0.delta.nearai_tool_result.output")
					}
					for _, path := range paths {
						parent, name := wireField(t, payload, strings.ReplaceAll(path, "FIELD", field))
						value, ok := parent[name].(string)
						if !ok {
							encoded, _ := json.Marshal(parent[name])
							value = string(encoded)
						}
						parent[name], err = encryptText(value, E2EEModelKey{algo, headers.Get("X-Client-Pub-Key")})
						if err != nil {
							t.Fatal(err)
						}
					}
					encoded, _ := json.Marshal(payload)
					var visible []byte
					if stream {
						source := io.NopCloser(bytes.NewReader(append(append([]byte("event: message\nid: event-1\ndata: "), encoded...), []byte("\n\ndata: [DONE]\n\ndata: ignored after [DONE]\n\n")...)))
						reader := prepared.DecryptSSE(source)
						visible, err = io.ReadAll(reader)
						reader.Close()
						if err == nil {
							if !bytes.Contains(visible, []byte("event: message\nid: event-1\n")) || !bytes.HasSuffix(visible, []byte("data: [DONE]\n\ndata: ignored after [DONE]\n\n")) {
								t.Fatal("SSE controls changed")
							}
							data, _ := sseData(bytes.SplitN(visible, []byte("\n\n"), 2)[0])
							visible = []byte(data)
						}
					} else {
						visible, err = prepared.DecryptJSON(encoded)
						_, wrongKeyErr := otherPrepared.DecryptJSON(encoded)
						requireCode(t, wrongKeyErr, "e2ee.decryption_failed")
					}
					if err != nil {
						t.Fatal(err)
					}
					var actual map[string]any
					if err := json.Unmarshal(visible, &actual); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(actual, expected) {
						t.Fatalf("response fields differ: %s", visible)
					}
				})
			}
		})
	}
}
