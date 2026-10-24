package artifact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

// bindProvenance checks claims only. Signature/certificate/log trust is always
// delegated to Attest; parsing a Sigstore bundle is not authentication.
func bindProvenance(data []byte, want Identity) error {
	var bundle struct {
		MediaType            string
		VerificationMaterial struct {
			Certificate struct{ RawBytes string }
			TlogEntries []json.RawMessage
		}
		DSSEEnvelope struct {
			PayloadType, Payload string
			Signatures           []json.RawMessage
		}
	}
	if decodeJSON(data, &bundle) != nil || bundle.MediaType != "application/vnd.dev.sigstore.bundle.v0.3+json" || bundle.DSSEEnvelope.PayloadType != "application/vnd.in-toto+json" || len(bundle.DSSEEnvelope.Signatures) == 0 || bundle.VerificationMaterial.Certificate.RawBytes == "" || len(bundle.VerificationMaterial.TlogEntries) == 0 {
		return fmt.Errorf("%w: unsupported/incomplete Sigstore bundle", ErrProvenance)
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(bundle.DSSEEnvelope.Payload)
	if err != nil {
		return fmt.Errorf("%w: DSSE payload", ErrProvenance)
	}
	var statement struct {
		Type    string `json:"_type"`
		Subject []struct {
			Name   string
			Digest map[string]string
		}
		PredicateType string
		Predicate     struct {
			BuildDefinition struct {
				BuildType          string
				ExternalParameters struct {
					Workflow struct{ Ref, Repository, Path string }
				}
				ResolvedDependencies []struct {
					URI    string
					Digest map[string]string
				}
			}
			RunDetails struct{ Builder struct{ ID string } }
		}
	}
	if decodeJSON(payload, &statement) != nil {
		return fmt.Errorf("%w: statement JSON", ErrProvenance)
	}
	def := statement.Predicate.BuildDefinition
	workflow := def.ExternalParameters.Workflow
	if statement.Type != "https://in-toto.io/Statement/v1" || statement.PredicateType != "https://slsa.dev/provenance/v1" || def.BuildType != "https://actions.github.io/buildtypes/workflow/v1" || len(statement.Subject) != 1 || statement.Subject[0].Name != want.Subject || statement.Subject[0].Digest["sha256"] != want.SHA256 || workflow.Ref != want.Ref || workflow.Repository != want.Repository || workflow.Path != want.Workflow || statement.Predicate.RunDetails.Builder.ID != want.Repository+"/"+want.Workflow+"@"+want.Ref {
		return fmt.Errorf("%w: subject/workflow mismatch", ErrProvenance)
	}
	expectedURI := "git+" + want.Repository + "@" + want.Ref
	matches := 0
	for _, dep := range def.ResolvedDependencies {
		if dep.URI == expectedURI {
			if dep.Digest["gitCommit"] != want.Commit {
				return fmt.Errorf("%w: source commit mismatch", ErrProvenance)
			}
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("%w: missing/ambiguous source commit", ErrProvenance)
	}
	return nil
}

// GitHub adds fields over time, so unknown fields are retained as raw evidence;
// duplicate names and excessive nesting are rejected to avoid parser ambiguity.
func decodeJSON(data []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return fmt.Errorf("JSON nesting limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return fmt.Errorf("duplicate/nonstring JSON field")
				}
				seen[name] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return json.Unmarshal(data, dst)
}
