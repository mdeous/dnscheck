package checker

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type IssueType string

const (
	IssueDanglingCname     IssueType = "dangling_cname_record"
	IssueDanglingNs                  = "dangling_ns_record"
	IssuePartialDanglingNs           = "partial_dangling_ns_record"
	IssueDanglingMx                  = "dangling_mx_record"
	IssueUnregistered                = "unregistered_domain"
	IssueUnregisteredNs              = "unregistered_ns_record"
	// IssueDanglingUnclaimable is a record that points at something broken
	// whose target cannot be claimed: a reserved name, or a delegation whose
	// nameservers are all registered to someone else. Not a takeover, but
	// still a misconfiguration worth fixing.
	IssueDanglingUnclaimable = "dangling_record_unclaimable"
)

// Exploitable reports whether an issue lets an attacker claim the target.
func (t IssueType) Exploitable() bool {
	return t != IssueDanglingUnclaimable
}

type DetectionMethod string

const (
	MethodPattern         DetectionMethod = "body_pattern"
	MethodNxdomain                        = "nxdomain"
	MethodHttpStatus                      = "http_status"
	MethodCnamePattern                    = "cname_body_pattern"
	MethodCnameNxdomain                   = "cname_nxdomain"
	MethodCnameHttpStatus                 = "cname_http_status"
	MethodServfail                        = "servfail"
	MethodSoaCheck                        = "soa_check"
	MethodNone                            = "not_vulnerable"
	MethodAPattern                        = "a_body_pattern"
	MethodANxdomain                       = "a_nxdomain"
	MethodAHttpStatus                     = "a_http_status"
)

type Match struct {
	Domain      string          `json:"domain"`
	Target      string          `json:"target"`
	Type        IssueType       `json:"type"`
	Method      DetectionMethod `json:"method"`
	Fingerprint *Fingerprint    `json:"fingerprint"`
	Confidence  ConfidenceLevel `json:"confidence"`
	Reasons     []string        `json:"reasons"`
}

// MarshalJSON adds the derived exploitable flag, so consumers can split
// takeover opportunities from plain misconfigurations without knowing the
// issue types.
func (m *Match) MarshalJSON() ([]byte, error) {
	type match Match
	return json.Marshal(struct {
		*match
		Exploitable bool `json:"exploitable"`
	}{match: (*match)(m), Exploitable: m.Exploitable()})
}

// Exploitable reports whether this finding is a takeover opportunity rather
// than a dangling record nobody can claim.
func (m *Match) Exploitable() bool {
	return m.Type.Exploitable()
}

func (m *Match) String() string {
	fpName := "n/a"
	if m.Fingerprint != nil {
		fpName = m.Fingerprint.Name
	}
	baseOutput := fmt.Sprintf("[service: %s] %s -> %s [type=%s method=%s] (confidence: %s)",
		fpName, m.Domain, m.Target, m.Type, m.Method, m.Confidence)

	if len(m.Reasons) > 0 {
		return baseOutput + fmt.Sprintf(" - %s", strings.Join(m.Reasons, ", "))
	}

	return baseOutput
}

type DomainFinding struct {
	Domain  string   `json:"domain"`
	Matches []*Match `json:"matches"`
}

type Findings struct {
	Data []*DomainFinding `json:"findings"`
}

func (f *Findings) Write(filePath string) error {
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("could not marshal results to JSON: %v", err)
	}
	err = os.WriteFile(filePath, data, 0600)
	if err != nil {
		return fmt.Errorf("could not write results to %s: %v", filePath, err)
	}
	return nil
}
