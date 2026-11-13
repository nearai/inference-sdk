package nearai

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestE2EEProtocolVectorsAndRoundtrip(t *testing.T) {
	seed := bytes.Repeat([]byte{11}, 32)
	hash := sha512.Sum512(seed)
	secret := hash[:32]
	secret[0] &= 248
	secret[31] &= 127
	secret[31] |= 64
	ecdsaSecret := make([]byte, 32)
	ecdsaSecret[31] = 1
	for _, v := range []struct {
		key              e2eeKey
		ciphertext, want string
	}{
		{
			e2eeKey{algo: Ed25519, secret: secret},
			"07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7ca0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b743d22a6968fbbdf88cd066c79b3dacd53a6991f06ce8c564e03b7eb60e2376",
			"fixed v2 vector",
		},
		{
			e2eeKey{algo: ECDSA, secret: ecdsaSecret},
			"04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a000102030405060708090a0bb70c17944e668fbe04a547595e40927c708a34b9e7c4cb5b9917a6fb2240653b2a142b86",
			"near-ai ecdsa vector",
		},
	} {
		got, e := decryptText(v.ciphertext, v.key)
		if e != nil || got != v.want {
			t.Fatalf("vector: %q %v", got, e)
		}
	}
	for _, algo := range []SigningAlgo{Ed25519, ECDSA} {
		key, e := newE2EEKey(algo)
		if e != nil {
			t.Fatal(e)
		}
		encrypted, e := encryptText("UTF-8: A é € 🌍", E2EEModelKey{algo, key.public})
		if e != nil {
			t.Fatal(e)
		}
		got, e := decryptText(encrypted, key)
		if e != nil || got != "UTF-8: A é € 🌍" {
			t.Fatalf("%q %v", got, e)
		}
		raw, _ := hex.DecodeString(encrypted)
		raw[len(raw)-1] ^= 1
		if _, e = decryptText(hex.EncodeToString(raw), key); e == nil {
			t.Fatal("accepted tampered AEAD")
		}
	}
}

func TestE2EEV3RichContentParts(t *testing.T) {
	for _, algo := range []SigningAlgo{ECDSA, Ed25519} {
		t.Run(string(algo), func(t *testing.T) {
			key, err := newE2EEKey(algo)
			if err != nil {
				t.Fatal(err)
			}
			cipher, err := encryptText("answer", E2EEModelKey{algo, key.public})
			if err != nil {
				t.Fatal(err)
			}
			for field, streaming := range map[string]bool{"message": false, "delta": true} {
				t.Run(field, func(t *testing.T) {
					makeBody := func(parts []any) (map[string]any, map[string]any) {
						message := map[string]any{"content": parts}
						return map[string]any{"choices": []any{map[string]any{field: message}}}, message
					}
					part := func() map[string]any { return map[string]any{"type": "text", "text": cipher} }
					body, message := makeBody([]any{part()})
					if err := decryptChat(body, key, streaming); err != nil {
						t.Fatal(err)
					}
					if objects(message["content"])[0]["text"] != "answer" {
						t.Fatal("rich text was not decrypted")
					}
					empty, _ := makeBody([]any{})
					if err := decryptChat(empty, key, streaming); err != nil {
						t.Fatal(err)
					}
					for _, invalid := range []any{"plaintext", 0, true, nil, []any{"nested"}} {
						body, _ := makeBody([]any{part(), invalid})
						requireCode(t, decryptChat(body, key, streaming), "e2ee.decryption_failed")
					}
				})
			}
		})
	}
}

func TestE2EEV3Vectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/e2ee-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Algo        SigningAlgo `json:"signing_algo"`
			ModelSecret string      `json:"model_secret"`
			ModelPublic string      `json:"model_public"`
			ReplyPublic string      `json:"reply_public"`
			AAD         string      `json:"aad"`
			Field       string      `json:"field"`
			Plaintext   string      `json:"plaintext"`
			Ciphertext  string      `json:"ciphertext"`
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixture.Vectors {
		t.Run(string(v.Algo), func(t *testing.T) {
			seed, _ := hex.DecodeString(v.ModelSecret)
			secret := seed
			if v.Algo == Ed25519 {
				h := sha512.Sum512(seed)
				secret = h[:32]
				secret[0] &= 248
				secret[31] &= 127
				secret[31] |= 64
			}
			key := e2eeKey{v.Algo, v.ModelPublic, secret}
			aad, err := requestAAD(v.Algo, v.ReplyPublic)
			aad = fieldAAD(aad, v.Field)
			if err != nil || hex.EncodeToString(aad) != v.AAD {
				t.Fatalf("AAD: %v", err)
			}
			plain, err := decryptTextWithAAD(v.Ciphertext, key, aad)
			if err != nil || plain != v.Plaintext {
				t.Fatalf("vector: %q %v", plain, err)
			}
			if v.Algo == ECDSA {
				canonical, err := requestAAD(v.Algo, v.ReplyPublic[2:])
				canonical = fieldAAD(canonical, v.Field)
				if err != nil || !bytes.Equal(canonical, aad) {
					t.Fatal("noncanonical reply key")
				}
			}
			cipher, err := encryptTextWithAAD(v.Plaintext, E2EEModelKey{v.Algo, v.ModelPublic}, aad)
			if err != nil {
				t.Fatal(err)
			}
			plain, err = decryptTextWithAAD(cipher, key, aad)
			if err != nil || plain != v.Plaintext {
				t.Fatalf("round trip: %q %v", plain, err)
			}
			wrongKey, _ := requestAAD(v.Algo, v.ModelPublic)
			wrongSuite := append([]byte(nil), aad...)
			wrongSuite[22] = 255
			for _, wrong := range [][]byte{nil, wrongKey, wrongSuite} {
				if _, err = decryptTextWithAAD(v.Ciphertext, key, wrong); err == nil {
					t.Fatal("accepted wrong AAD")
				}
			}

			request, err := http.NewRequest("POST", "https://example.test/v1/chat/completions", strings.NewReader(`{"model":"test","messages":[{"role":"user","content":"private prompt"}],"tools":[{"type":"function","function":{"name":"private_tool","parameters":{"type":"object"}}}]}`))
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := PrepareE2EEChatRequest(request, E2EEModelKey{v.Algo, v.ModelPublic})
			if err != nil {
				t.Fatal(err)
			}
			if prepared.Request.Header.Get("X-Encryption-Version") != "3" {
				t.Fatal("missing v3 header")
			}
			preparedAAD, err := requestAAD(v.Algo, prepared.Request.Header.Get("X-Client-Pub-Key"))
			if err != nil {
				t.Fatal(err)
			}
			var requestBody map[string]any
			if err := json.NewDecoder(prepared.Request.Body).Decode(&requestBody); err != nil {
				t.Fatal(err)
			}
			tool := object(objects(requestBody["tools"])[0]["function"])
			for _, field := range []struct{ cipher, label, expected string }{
				{objects(requestBody["messages"])[0]["content"].(string), "messages[].content", "private prompt"},
				{tool["name"].(string), "tools[].function.name", "private_tool"},
				{tool["parameters"].(string), "tools[].function.parameters", `{"type":"object"}`},
			} {
				plain, err := decryptTextWithAAD(field.cipher, key, fieldAAD(preparedAAD, field.label))
				if err != nil || plain != field.expected {
					t.Fatalf("prepared field: %q %v", plain, err)
				}
				if _, err := decryptText(field.cipher, key); err == nil {
					t.Fatal("request accepted without AAD")
				}
				if _, err := decryptTextWithAAD(field.cipher, key, fieldAAD(preparedAAD, "tool_choice.function.name")); err == nil {
					t.Fatal("request accepted in another field")
				}
			}

			for _, text := range []string{
				`{"choices":[{"message":{},"logprobs":{"content":[{"bytes":[115]}]}}]}`,
				`{"choices":[{"message":{"tool_calls":[{"function":{"arguments":"{}"}}]}}]}`,
				`{"choices":[{"message":{"tool_calls":[{"function":{"arguments":{"secret":true}}}]}}]}`,
			} {
				var body map[string]any
				json.Unmarshal([]byte(text), &body)
				if err := decryptChat(body, key, false); err == nil {
					t.Fatal("accepted clear protected field")
				}
			}
		})
	}
}

func TestE2EEV3RejectsMalformedResponseContainers(t *testing.T) {
	for _, algo := range []SigningAlgo{ECDSA, Ed25519} {
		key, err := newE2EEKey(algo)
		if err != nil {
			t.Fatal(err)
		}
		prepared := &PreparedE2EEChatRequest{key: key}
		for _, choice := range []string{
			`{"message":{"tool_calls":{"function":{"arguments":"plaintext"}}}}`,
			`{"message":{"tool_calls":[null]}}`,
			`{"message":{"tool_calls":[{"function":["plaintext"]}]}}`,
			`{"message":{"audio":[{"data":"plaintext"}]}}`,
			`{"message":{"function_call":["plaintext"]}}`,
			`{"logprobs":[]}`,
			`{"logprobs":{"content":{"token":"plaintext"}}}`,
			`{"logprobs":{"content":[null]}}`,
			`{"logprobs":{"content":[{"top_logprobs":{"token":"plaintext"}}]}}`,
		} {
			body := `{"id":"chat-containers","choices":[` + choice + `]}`
			_, err := prepared.DecryptJSON([]byte(body))
			requireCode(t, err, "e2ee.decryption_failed")
			chunk := strings.Replace(body, `"message":`, `"delta":`, 1)
			stream := prepared.DecryptSSE(io.NopCloser(strings.NewReader("data: " + chunk + "\n\n")))
			_, err = io.ReadAll(stream)
			stream.Close()
			requireCode(t, err, "e2ee.decryption_failed")
		}
		var valid map[string]any
		json.Unmarshal([]byte(`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-1"}],"audio":null},"logprobs":null}]}`), &valid)
		if err := decryptChat(valid, key, true); err != nil {
			t.Fatal(err)
		}
	}
}
