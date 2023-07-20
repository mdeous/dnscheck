package checker

import (
	_ "embed"
	"encoding/json"
	"github.com/mdeous/dnscheck/internal/log"
	"os"
)

//go:embed can-i-take-over-xyz/fingerprints.json
var fpData []byte

const EdgeCase = "Edge case"

type Fingerprint struct {
	CNames        []string `json:"cname"`
	Discussion    string   `json:"discussion"`
	Documentation string   `json:"documentation"`
	Pattern       string   `json:"fingerprint"`
	HttpStatus    int      `json:"http_status"`
	NXDomain      bool     `json:"nxdomain"`
	Name          string   `json:"service"`
	Vulnerable    bool     `json:"vulnerable"`
	Status        string   `json:"status"`
}

func (f *Fingerprint) HasCNames() bool {
	return len(f.CNames) > 0
}

func (f *Fingerprint) HasPattern() bool {
	return f.Pattern != ""
}

func (f *Fingerprint) HasHttpStatus() bool {
	return f.HttpStatus != 0
}

func (f *Fingerprint) IsEdgeCase() bool {
	return f.Status == EdgeCase
}

func LoadFingerprints(customFile string, includeEdgeCases bool) []*Fingerprint {
	var allFps []*Fingerprint
	var fingerprints []*Fingerprint

	// load fingerprints file
	if customFile != "" {
		// load from user-provided file
		log.Info("Loading fingerprints from %s", customFile)
		content, err := os.ReadFile(customFile)
		if err != nil {
			log.Fatal("Unable to read %s: %v", customFile, err)
		}
		fpData = content
	}
	err := json.Unmarshal(fpData, &allFps)
	if err != nil {
		log.Fatal("Unable to load services: %v", err)
	}

	// filter out unwanted fingerprints
	for _, fp := range allFps {
		if fp.Vulnerable || (includeEdgeCases && fp.Status == EdgeCase) {
			if fp.HasCNames() || fp.HasPattern() || fp.NXDomain || fp.HasHttpStatus() {
				fingerprints = append(fingerprints, fp)
			}
		}
	}

	return fingerprints
}
