package checker

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type Finding struct {
	Domain  string          `json:"domain"`
	Target  string          `json:"target"`
	Service string          `json:"service"`
	Type    IssueType       `json:"type"`
	Method  DetectionMethod `json:"method"`
}

type Findings struct {
	Data []*Finding `json:"findings"`
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