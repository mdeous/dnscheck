package checker

import (
	"encoding/json"
	"fmt"
	"os"
)

type IssueType string

const (
	IssueDanglingCname   IssueType = "dangling_cname_record"
	IssueDanglingNs                = "dangling_ns_record"
	IssuePartialDanglingNs         = "partial_dangling_ns_record"
	IssueUnregistered              = "unregistered_domain"
	IssueUnregisteredNs            = "unregistered_ns_record"
)

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
}

func (m *Match) String() string {
	fpName := "n/a"
	if m.Fingerprint != nil {
		fpName = m.Fingerprint.Name
	}
	return fmt.Sprintf("[service: %s] %s -> %s [type=%s method=%s] (confidence: %s)", 
		fpName, m.Domain, m.Target, m.Type, m.Method, m.Confidence)
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
