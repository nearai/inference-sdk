package nearai

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
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
		encrypted, e := encryptText("private 日本語", E2EEModelKey{algo, key.public})
		if e != nil {
			t.Fatal(e)
		}
		got, e := decryptText(encrypted, key)
		if e != nil || got != "private 日本語" {
			t.Fatalf("%q %v", got, e)
		}
		raw, _ := hex.DecodeString(encrypted)
		raw[len(raw)-1] ^= 1
		if _, e = decryptText(hex.EncodeToString(raw), key); e == nil {
			t.Fatal("accepted tampered AEAD")
		}
	}
}
