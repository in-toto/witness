package policy

import (
	"time"
)

const PolicyPredicate = "https://witness.testifysec.com/policy/v0.1"

type Policy struct {
	Expires time.Time       `json:"expires"`
	Roots   map[string]Root `json:"roots,omitempty"`
	Steps   []Step          `json:"steps"`
}

type Root struct {
	Certificate   []byte   `json:"certificate"`
	Intermediates [][]byte `json:"intermediates,omitempty"`
}

type Step struct {
	Name          string      `json:"name"`
	Functionaries Functionary `json:"functionaries"`
	Attestations  Attestation `json:"attestation"`
}

type Functionary struct {
	Type           string         `json:"type"`
	CertConstraint CertConstraint `json:"certConstraint,omitempty"`
}

type Attestation struct {
	Predicate string   `json:"predicate"`
	Policies  []string `json:"policies"`
}

type CertConstraint struct {
	Roots []string `json:"roots"`
}
