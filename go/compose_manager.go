package nearai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"
)

// ComposeManagerAction retains every signed string or string-array field.
// Known fields are action, timestamp, image, commit, file, file_sha256 and services.
type ComposeManagerAction map[string]any

type ComposeManagerAttestation struct {
	Actions           []ComposeManagerAction `json:"actions"`
	ActionsHash       string                 `json:"actions_hash"`
	Nonce             string                 `json:"nonce"`
	IntelQuote        string                 `json:"quote"`
	EventLog          json.RawMessage        `json:"event_log"`
	ReportedQuoteData string                 `json:"report_data"`
}

// VerifiedComposeManagerAttestation authenticates recorded deployment intent,
// not successful execution, current containers, or a unique CVM identity.
type VerifiedComposeManagerAttestation struct {
	Actions             []ComposeManagerAction
	TCBStatus           string
	AdvisoryIDs         []string
	RuntimeMeasurements RuntimeMeasurements
}

// cloneDeployment copies mutable manager fields for independent result values.
func cloneDeployment(deployment MeasuredDeployment) MeasuredDeployment {
	if deployment.ComposeManager != nil {
		manager := *deployment.ComposeManager
		manager.AdvisoryIDs = slices.Clone(manager.AdvisoryIDs)
		manager.Actions = slices.Clone(manager.Actions)
		for i, action := range manager.Actions {
			copied := maps.Clone(action)
			for key, value := range copied {
				if values, ok := value.([]string); ok {
					copied[key] = slices.Clone(values)
				}
			}
			manager.Actions[i] = copied
		}
		deployment.ComposeManager = &manager
	}
	return deployment
}

func (a *ComposeManagerAction) UnmarshalJSON(raw []byte) error {
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for key, value := range fields {
		switch v := value.(type) {
		case string:
			if key == "services" {
				return fmt.Errorf("services must be a string array")
			}
		case []any:
			if key == "action" || key == "timestamp" || key == "image" || key == "commit" || key == "file" || key == "file_sha256" {
				return fmt.Errorf("%s must be a string", key)
			}
			strings := make([]string, len(v))
			for i, item := range v {
				str, ok := item.(string)
				if !ok {
					return fmt.Errorf("%s must contain strings", key)
				}
				strings[i] = str
			}
			fields[key] = strings
		default:
			return fmt.Errorf("%s must be a string or string array", key)
		}
	}
	if _, ok := fields["action"].(string); !ok {
		return fmt.Errorf("action missing")
	}
	if _, ok := fields["timestamp"].(string); !ok {
		return fmt.Errorf("timestamp missing")
	}
	*a = fields
	return nil
}

func actionString(a ComposeManagerAction, key string) string {
	value, _ := a[key].(string)
	return value
}

// JSON strings use UTF-8, including U+2028/U+2029; HTML escaping would change the log hash.
func canonicalString(s string) string {
	var out bytes.Buffer
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 32 {
				fmt.Fprintf(&out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}
func canonicalActions(actions []ComposeManagerAction) ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('[')
	for i, action := range actions {
		// Validate caller-constructed values using the same wire boundary.
		raw, err := json.Marshal(action)
		if err != nil {
			return nil, err
		}
		var checked ComposeManagerAction
		if err = json.Unmarshal(raw, &checked); err != nil {
			return nil, err
		}
		if i > 0 {
			out.WriteByte(',')
		}
		out.WriteByte('{')
		keys := make([]string, 0, len(checked))
		for key := range checked {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for j, key := range keys {
			if j > 0 {
				out.WriteByte(',')
			}
			out.WriteString(canonicalString(key))
			out.WriteByte(':')
			switch v := checked[key].(type) {
			case string:
				out.WriteString(canonicalString(v))
			case []string:
				out.WriteByte('[')
				for k, str := range v {
					if k > 0 {
						out.WriteByte(',')
					}
					out.WriteString(canonicalString(str))
				}
				out.WriteByte(']')
			}
		}
		out.WriteByte('}')
	}
	out.WriteByte(']')
	return out.Bytes(), nil
}

func verifyComposeManager(ctx context.Context, a ComposeManagerAttestation, appCompose, nonce string, o VerificationOptions) (*VerifiedComposeManagerAttestation, error) {
	if !sameHex(a.Nonce, nonce) {
		return nil, failure("binding.nonce_mismatch", nil)
	}
	q, err := verifyQuote(ctx, a.IntelQuote, o)
	if err != nil {
		return nil, err
	}
	nb, err := hexSize(nonce, 32)
	if err != nil || !bytes.Equal(q.ReportData[32:], nb) {
		return nil, failure("binding.nonce_mismatch", err)
	}
	if a.ReportedQuoteData != "" {
		data, err := hexSize(a.ReportedQuoteData, 64)
		if err != nil || !bytes.Equal(data, q.ReportData) {
			return nil, failure("binding.report_data_mismatch", err)
		}
	}
	canonical, err := canonicalActions(a.Actions)
	if err != nil {
		return nil, failure("binding.compose_manager_actions_mismatch", err)
	}
	digest := sha256.Sum256(canonical)
	advertised, err := hexSize(a.ActionsHash, 32)
	if err != nil || !bytes.Equal(advertised, digest[:]) || !bytes.Equal(q.ReportData[:32], digest[:]) {
		return nil, failure("binding.compose_manager_actions_mismatch", err)
	}
	compose := sha256.Sum256([]byte(appCompose))
	if q.MRConfigID[0] != 1 || !bytes.Equal(q.MRConfigID[1:33], compose[:]) {
		return nil, failure("measurement.app_compose_mrconfigid_mismatch", nil)
	}
	measurements, err := replayEvents(a.EventLog, q.RTMR3)
	if err != nil {
		return nil, err
	}
	var actions []ComposeManagerAction
	if err = json.Unmarshal(canonical, &actions); err != nil {
		return nil, err
	}
	return &VerifiedComposeManagerAttestation{Actions: actions, TCBStatus: q.TCBStatus, AdvisoryIDs: append([]string(nil), q.AdvisoryIDs...), RuntimeMeasurements: measurements}, nil
}
