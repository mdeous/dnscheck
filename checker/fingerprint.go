package checker

import (
	_ "embed"
	"encoding/json"
	"github.com/mdeous/dnscheck/internal/log"
	"os"
)

//go:embed can-i-take-over-xyz/fingerprints.json
var fpData []byte

type Fingerprint struct {
	CNames        []string `json:"cname"`
	Discussion    string   `json:"discussion"`
	Documentation string   `json:"documentation"`
	Pattern       string   `json:"fingerprint"`
	HttpStatus    int      `json:"http_status"`
	NXDomain      bool     `json:"nxdomain"`
	Name          string   `json:"service"`
	Vulnerable    bool     `json:"vulnerable"`
}

func LoadFingerprints(customFile string) []*Fingerprint {
	//var data Data
	var fingerprints []*Fingerprint
	if customFile != "" {
		// load fingerprints from user-provided file
		log.Info("Loading fingerprints from %s", customFile)
		content, err := os.ReadFile(customFile)
		if err != nil {
			log.Fatal("Unable to read %s: %v", customFile, err)
		}
		fpData = content
	}
	err := json.Unmarshal(fpData, &fingerprints)
	if err != nil {
		log.Fatal("Unable to load services: %v", err)
	}
	return fingerprints
}
