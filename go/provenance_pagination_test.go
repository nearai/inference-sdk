package nearai

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestProvenancePaginationLimits(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		pages, pageBytes, calls int
		code                    string
	}{
		{"exact page count", 32, 128, 32, ""},
		{"too many unique cursors", 33, 128, 32, "api.invalid_response"},
		{"exact total bytes", 4, 16 << 20, 4, ""},
		{"cumulative overflow", 5, 13 << 20, 5, "api.body_too_large"},
	} {
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/chunked=%t", tc.name, chunked), func(t *testing.T) {
				var calls atomic.Int32
				// A finite final page lets the unfixed implementation terminate.
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					page := 1
					if after := r.URL.Query().Get("after"); after != "" {
						var err error
						page, err = strconv.Atoi(after)
						if err != nil {
							t.Error(err)
						}
					}
					if page < tc.pages {
						w.Header().Set("Link", fmt.Sprintf("<http://%s%s?after=%d>; rel=\"next\"", r.Host, r.URL.Path, page+1))
					}
					body := []byte(`{"attestations":[{"bundle":{"ok":true}}]}`)
					body = append(body, bytes.Repeat([]byte(" "), tc.pageBytes-len(body))...)
					if chunked {
						w.(http.Flusher).Flush()
					} else {
						w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					}
					_, _ = w.Write(body)
				}))
				defer server.Close()
				bundles, err := FetchImageProvenance(context.Background(), "nearai/compose-manager", "sha256:"+strings.Repeat("ab", 32), ProvenanceOptions{GitHubProxyURL: server.URL, HTTPClient: server.Client()})
				if tc.code != "" {
					requireCode(t, err, tc.code)
					if len(bundles) != 0 {
						t.Fatal("returned partial provenance")
					}
				} else if err != nil || len(bundles) != tc.pages {
					t.Fatalf("bundles=%d error=%v", len(bundles), err)
				}
				if int(calls.Load()) != tc.calls {
					t.Fatalf("sent %d requests; want %d", calls.Load(), tc.calls)
				}
			})
		}
	}
}
