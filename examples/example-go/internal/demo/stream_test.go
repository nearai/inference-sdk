package demo

import (
	"strings"
	"testing"
)

func TestIncrementalOutput(t *testing.T) {
	for _, separator := range []string{"\n", "\r\n", "\r"} {
		event := strings.ReplaceAll("data: {\"id\":\"chat-1\",\ndata: \"choices\":[{\"delta\":{\"content\":\"Hello 🌍\"}}]}\n\n", "\n", separator)
		for split := 0; split <= len(event); split++ {
			decoder := new(EventDecoder)
			first, err := decoder.Push([]byte(event[:split]), false)
			if err != nil {
				t.Fatal(err)
			}
			second, err := decoder.Push([]byte(event[split:]), false)
			if err != nil {
				t.Fatal(err)
			}
			// A lone CR waits for the next byte to distinguish it from CRLF.
			last, err := decoder.Push([]byte(":"), false)
			if err != nil {
				t.Fatal(err)
			}
			values := append(append(first, second...), last...)
			if len(values) != 1 || textDelta(values[0]) != "Hello 🌍" || decoder.Done {
				t.Fatalf("text was not emitted before DONE at split %d: %v", split, values)
			}
		}
		raw := []byte(event + "data: [DONE]" + separator + separator)
		if id, err := CompletionID(raw, true); err != nil || id != "chat-1" {
			t.Fatalf("ID: %q, %v", id, err)
		}
		if _, err := CompletionID([]byte(event), true); err == nil {
			t.Fatal("truncated stream accepted")
		}
	}
}

func TestInvalidStream(t *testing.T) {
	if _, err := Events([]byte("data: {\"type\":\"error\"}\n\n")); err == nil {
		t.Fatal("error event accepted")
	}
	if _, err := CompletionID([]byte("data: {\"id\":\"one\"}\n\ndata: {\"id\":\"two\"}\n\ndata: [DONE]\n\n"), true); err == nil {
		t.Fatal("conflicting IDs accepted")
	}
}

func TestOnlyInitialBOMIsRemoved(t *testing.T) {
	event := "data: {\"id\":\"chat-fixture\",\"choices\":[{\"delta\":{\"content\":\"Hello 🌍\"}}]}\n\n"
	for _, prefix := range []string{"\ufeff", "\ufeff\ufeffdata: {\"error\":\"ignored\"}\n\n", ": first\n\n\ufeffdata: {\"error\":\"ignored\"}\n\n"} {
		record := []byte(prefix + event)
		for split := 0; split <= len(record); split++ {
			decoder := new(EventDecoder)
			first, err := decoder.Push(record[:split], false)
			if err != nil {
				t.Fatal(err)
			}
			second, err := decoder.Push(record[split:], false)
			if err != nil {
				t.Fatal(err)
			}
			values := append(first, second...)
			if len(values) != 1 || textDelta(values[0]) != "Hello 🌍" || values[0]["id"] != "chat-fixture" || decoder.Done {
				t.Fatalf("BOM handling at split %d: %v", split, values)
			}
		}
	}
}
