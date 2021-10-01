package checks

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type IssueType string

const (
	IssueTargetNoResolve IssueType = "target might be unclaimed"
	IssueCnameTakeover             = "points to unclaimed resource"
	IssueNsTakeover                = "unclaimed zone delegation"
)

type DetectionMethod string

const (
	MethodCnameOnly    DetectionMethod = "CNAME only"
	MethodPatternOnly                  = "response body only"
	MethodCnamePattern                 = "CNAME + response body"
	MethodCnameLookup                  = "CNAME target lookup"
	MethodServfail                     = "SERVFAIL check"
)

type Finding struct {
	Domain  string          `json:"domain"`
	Target  string          `json:"target"`
	Service string          `json:"service"`
	Type    IssueType       `json:"type"`
	Method  DetectionMethod `json:"method"`
}

type Findings struct {
	Data []*Finding `json:"data"`
}

func (f *Findings) Write(filePath string) error {
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("could not marshal results to JSON: %v", err)
	}
	err = ioutil.WriteFile(filePath, data, 0600)
	if err != nil {
		return fmt.Errorf("could not write results to %s: %v", filePath, err)
	}
	return nil
}
