package dcap

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// The signed sample and collateral are upstream MIT fixtures from DCAP QVL
// v0.6.5 (884e22ce767f31fd5d5a6672511519fc7975cde0). Use their validity window
// so this exercises offline cryptographic verification without trusting a clock.
func TestNativeTDXVerification(t *testing.T) {
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
	report, e := Verify(quote, &collateral, uint64(latest-1))
	if e != nil {
		t.Fatal(e)
	}
	if report.Status != "UpToDate" || report.Report.Type != "TD10" || len(report.Report.ReportData) != 64 {
		t.Fatalf("unexpected report %+v", report)
	}
	quote[100] ^= 1
	if _, e = Verify(quote, &collateral, uint64(latest-1)); e == nil {
		t.Fatal("tampered quote accepted")
	}
}
func TestMalformedQuoteCallback(t *testing.T) {
	if _, e := ParseQuote([]byte{0xff}); e == nil {
		t.Fatal("malformed quote accepted")
	}
}
