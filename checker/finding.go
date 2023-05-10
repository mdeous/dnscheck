package checker

import (
	"encoding/json"
	"fmt"
	"os"
)

type Match struct {
	Target      string          `json:"target"`
	Service     string          `json:"service"`
	Type        IssueType       `json:"type"`
	Method      DetectionMethod `json:"method"`
	Fingerprint *Fingerprint    `json:"fingerprint"`
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
