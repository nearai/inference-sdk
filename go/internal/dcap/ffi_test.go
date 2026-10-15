package dcap

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// The signed sample and collateral are upstream MIT fixtures from DCAP QVL
// v0.6.5 (884e22ce767f31fd5d5a6672511519fc7975cde0). Use their validity window
// so this exercises offline cryptographic verification without trusting a clock.
func TestOfflineTDXVerification(t *testing.T) {
	quote, collateral, now := offlineFixture(t)
	report, e := Verify(quote, collateral, now)
	if e != nil {
		t.Fatal(e)
	}
	expected, err := os.ReadFile("testdata/native_verified_report.json")
	if err != nil {
		t.Fatal(err)
	}
	var baseline VerifiedReport
	if err := json.Unmarshal(expected, &baseline); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(report)
	want, _ := json.Marshal(&baseline)
	if !bytes.Equal(got, want) {
		t.Fatal("verification evidence differs from native baseline")
	}
	if report.Status != "UpToDate" || report.Report.Type != "TD10" || len(report.Report.ReportData) != 64 {
		t.Fatalf("unexpected report %+v", report)
	}
	if _, err := Verify(quote, collateral, now+2); err == nil {
		t.Fatal("expired collateral accepted")
	}
	if _, err := VerifyWithRootCA(quote, collateral, []byte("untrusted root"), now); err == nil {
		t.Fatal("invalid root accepted")
	}

	// Isolated guest instances must produce identical evidence concurrently.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := Verify(quote, collateral, now)
			if err != nil || got == nil || got.Status != report.Status {
				t.Errorf("concurrent verification: %v", err)
			}
		}()
	}
	wg.Wait()

	quote[100] ^= 1
	if _, e = Verify(quote, collateral, now); e == nil {
		t.Fatal("tampered quote accepted")
	}
}
func TestMalformedQuote(t *testing.T) {
	if _, e := ParseQuote([]byte{0xff}); e == nil {
		t.Fatal("malformed quote accepted")
	}
}

func TestVerificationCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := VerifyContext(ctx, []byte{0xff}, nil, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func offlineFixture(t testing.TB) ([]byte, *QuoteCollateralV3, uint64) {
	t.Helper()
	quote, e := os.ReadFile("testdata/tdx_quote")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("testdata/tdx_quote_collateral.json")
	if e != nil {
		t.Fatal(e)
	}
	var collateral QuoteCollateralV3
	if e = json.Unmarshal(raw, &collateral); e != nil {
		t.Fatal(e)
	}
	earliest, latest := int64(0), int64(1<<62)
	for _, raw := range []string{collateral.TCBInfo, collateral.QEIdentity} {
		var validity struct{ IssueDate, NextUpdate string }
		if e = json.Unmarshal([]byte(raw), &validity); e != nil {
			t.Fatal(e)
		}
		a, e := time.Parse(time.RFC3339, validity.IssueDate)
		if e != nil {
			t.Fatal(e)
		}
		b, e := time.Parse(time.RFC3339, validity.NextUpdate)
		if e != nil {
			t.Fatal(e)
		}
		earliest = max(earliest, a.Unix())
		latest = min(latest, b.Unix())
	}
	for _, raw := range [][]byte{collateral.RootCACRL, collateral.PCKCRL} {
		crl, e := x509.ParseRevocationList(raw)
		if e != nil {
			t.Fatal(e)
		}
		earliest = max(earliest, crl.ThisUpdate.Unix())
		if !crl.NextUpdate.IsZero() {
			latest = min(latest, crl.NextUpdate.Unix())
		}
	}
	if latest <= earliest {
		t.Fatal("invalid fixture validity window")
	}
	return quote, &collateral, uint64(latest - 1)
}

func BenchmarkOfflineTDXVerification(b *testing.B) {
	quote, collateral, now := offlineFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Verify(quote, collateral, now); err != nil {
			b.Fatal(err)
		}
	}
}
