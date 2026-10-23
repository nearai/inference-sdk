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
				bundles, err := FetchImageProvenance(context.Background(), "nearai/compose-manager", "sha256:"+strings.Repeat("ab", 32), ProvenanceOptions{GitHubAPIURL: server.URL, HTTPClient: server.Client()})
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

func TestProvenancePaginationLinkLimits(t *testing.T) {
	link := func(query string) string { return "<https://example.test/?" + query + ">; rel=\"next\"" }
	next := link("after=next")
	padding := func(size int) string { return strings.Repeat("x", size) }
	for _, tc := range []struct {
		name  string
		links []string
		valid bool
	}{
		{"exact Link bytes", []string{next + "; title=\"" + padding(8192-len(next)-10) + "\""}, true},
		{"oversized Link", []string{next + "; title=\"" + padding(8193-len(next)-10) + "\""}, false},
		{"exact combined Link bytes", []string{next, padding(8192 - len(next) - 1)}, true},
		{"oversized combined Link bytes", []string{next, padding(8193 - len(next) - 1)}, false},
		{"exact encoded cursor", []string{link("after=" + strings.Repeat("x", 4096-6))}, true},
		{"oversized encoded cursor", []string{link("after=" + strings.Repeat("x", 4097-6))}, false},
		{"exact reencoded cursor", []string{link("after=" + strings.Repeat("!", 1363) + "x")}, true},
		{"oversized reencoded cursor", []string{link("after=" + strings.Repeat("!", 1364))}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					for _, value := range tc.links {
						w.Header().Add("Link", value)
					}
				}
				_, _ = w.Write([]byte(`{"attestations":[{"bundle":{"ok":true}}]}`))
			}))
			defer server.Close()
			bundles, err := FetchImageProvenance(context.Background(), "nearai/compose-manager", "sha256:"+strings.Repeat("ab", 32), ProvenanceOptions{GitHubAPIURL: server.URL, HTTPClient: server.Client()})
			if tc.valid {
				if err != nil || len(bundles) != 2 || calls.Load() != 2 {
					t.Fatalf("bundles=%d calls=%d error=%v", len(bundles), calls.Load(), err)
				}
			} else {
				requireCode(t, err, "api.invalid_response")
				if len(bundles) != 0 || calls.Load() != 1 {
					t.Fatalf("bundles=%d calls=%d", len(bundles), calls.Load())
				}
			}
		})
	}
}

func TestProvenanceAttestationCount(t *testing.T) {
	for _, count := range []int{100, 101} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			body := `{"attestations":[` + strings.Repeat(`{"bundle":{}},`, count-1) + `{"bundle":{}}]}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			bundles, err := FetchImageProvenance(context.Background(), "nearai/compose-manager", "sha256:"+strings.Repeat("ab", 32), ProvenanceOptions{GitHubAPIURL: server.URL})
			if count == 100 {
				if err != nil || len(bundles) != count {
					t.Fatalf("bundles=%d error=%v", len(bundles), err)
				}
			} else {
				requireCode(t, err, "api.invalid_response")
				if len(bundles) != 0 {
					t.Fatal("returned partial provenance")
				}
			}
		})
	}
}
