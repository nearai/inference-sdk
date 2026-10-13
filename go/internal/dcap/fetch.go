package dcap

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// GetCollateral fetches collateral from a PCCS server for a given quote.
func GetCollateral(ctx context.Context, pccsURL string, rawQuote []byte) (*QuoteCollateralV3, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	if pccsURL == "" {
		return nil, fmt.Errorf("dcap: empty PCCS URL input")
	}
	if len(rawQuote) == 0 {
		return nil, fmt.Errorf("dcap: empty quote input")
	}

	q, err := ParseQuoteContext(ctx, rawQuote)
	if err != nil {
		return nil, fmt.Errorf("dcap: failed to parse quote: %w", err)
	}

	client := &http.Client{
		Timeout:       httpTimeout,
		Transport:     contextTransport{ctx},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// Get PCK certificate chain
	var pckChain string
	switch {
	case q.CertType == 5:
		// cert_type 5: PCK cert chain is embedded in the quote
		pckChain = q.CertChainPEM
	case q.CertType == 2 || q.CertType == 3:
		// cert_type 2/3: fetch PCK cert from PCCS using encrypted PPID
		if q.CertPCESVN == nil {
			return nil, fmt.Errorf("dcap: cert_type %d but missing encrypted PPID params", q.CertType)
		}
		pckChain, err = fetchPCKCertificate(client, pccsURL, q)
		if err != nil {
			return nil, fmt.Errorf("dcap: failed to fetch PCK certificate: %w", err)
		}
	default:
		return nil, fmt.Errorf("dcap: unsupported cert_type %d", q.CertType)
	}

	// Extract FMSPC and CA from the PCK certificate chain
	fmspc, ca, err := extractFMSPCAndCA(pckChain)
	if err != nil {
		return nil, fmt.Errorf("dcap: failed to extract FMSPC/CA: %w", err)
	}

	isSGX := q.QuoteType == "SGX"
	coll, err := getCollateralForFMSPCImpl(client, pccsURL, fmspc, ca, isSGX)
	if err != nil {
		return nil, err
	}

	// Attach the PCK certificate chain for offline verification
	coll.PCKCertificateChain = pckChain
	return coll, nil
}

// GetCollateralForFMSPC fetches collateral for a known FMSPC and CA type.
func GetCollateralForFMSPC(pccsURL, fmspc, ca string, isSGX bool) (*QuoteCollateralV3, error) {
	if pccsURL == "" {
		return nil, fmt.Errorf("dcap: empty PCCS URL input")
	}
	if fmspc == "" {
		return nil, fmt.Errorf("dcap: empty FMSPC input")
	}
	if ca == "" {
		return nil, fmt.Errorf("dcap: empty CA input")
	}

	client := &http.Client{Timeout: httpTimeout}
	return getCollateralForFMSPCImpl(client, pccsURL, fmspc, ca, isSGX)
}

// GetCollateralAndVerify fetches collateral and verifies in one call.
func GetCollateralAndVerify(rawQuote []byte, pccsURL string) (*VerifiedReport, error) {
	coll, err := GetCollateral(context.Background(), pccsURL, rawQuote)
	if err != nil {
		return nil, err
	}

	// Parse quote to check if it has a PCK certificate chain
	q, err := ParseQuote(rawQuote)
	if err != nil {
		return nil, err
	}

	// If the quote has an embedded cert chain, attach it to collateral
	if q.CertChainPEM != "" && coll.PCKCertificateChain == "" {
		coll.PCKCertificateChain = q.CertChainPEM
	}

	nowSecs := uint64(time.Now().Unix())
	return Verify(rawQuote, coll, nowSecs)
}

// Context is installed on every collateral request, including concurrent fetches.
type contextTransport struct{ ctx context.Context }

func (t contextTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return http.DefaultTransport.RoundTrip(r.Clone(t.ctx))
}
