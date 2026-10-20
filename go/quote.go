package nearai

import (
	"context"
	"time"

	dcap "github.com/nearai/inference-sdk/go/internal/dcap"
)

// CreateTDXQuoteVerifier uses DCAP QVL's Intel production root and fresh PCCS
// collateral. An empty base URL selects https://cloud.near.ai/api/proxy/pccs.
// Collateral requests honor context cancellation.
func CreateTDXQuoteVerifier(pccsBaseURL string) QuoteVerifier {
	if pccsBaseURL == "" {
		pccsBaseURL = "https://cloud.near.ai/api/proxy/pccs"
	}
	return func(ctx context.Context, encoded string) (QuoteVerificationResult, error) {
		var result QuoteVerificationResult
		if e := ctx.Err(); e != nil {
			return result, e
		}
		raw, e := unhex(encoded)
		if e != nil {
			return result, failure("quote.verification_failed", e)
		}
		if _, e = dcap.ParseQuoteContext(ctx, raw); e != nil {
			return result, failure("quote.verification_failed", e)
		}
		collateral, e := dcap.GetCollateral(ctx, pccsBaseURL, raw)
		if e != nil {
			return result, &Error{Code: "quote.collateral_unavailable", Retryable: true, Cause: e}
		}
		if e = ctx.Err(); e != nil {
			return result, e
		}
		verified, e := dcap.VerifyContext(ctx, raw, collateral, uint64(time.Now().Unix()))
		if e != nil {
			return result, failure("quote.verification_failed", e)
		}
		report := verified.Report
		if (report.Type != "TD10" && report.Type != "TD15") || len(report.TdAttributes) != 8 {
			return result, failure("quote.unsupported_report_type", nil)
		}
		return QuoteVerificationResult{
			TCBStatus:    verified.Status,
			AdvisoryIDs:  verified.AdvisoryIDs,
			DebugEnabled: report.TdAttributes[0]&1 != 0,
			ReportData:   report.ReportData,
			MRConfigID:   report.MrConfigID,
			RTMR3:        report.RTMR3,
		}, ctx.Err()
	}
}
