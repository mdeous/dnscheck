package checker

import (
	_ "embed"
	"encoding/json"
	"github.com/mdeous/dnscheck/log"
	"io"
	"net/http"
	"os"
)

const FingerprintsUrl = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"

type Fingerprint struct {
	CNames     []string `json:"cname"`
	Pattern    string   `json:"fingerprint"`
	HttpStatus int      `json:"http_status"`
	NXDomain   bool     `json:"nxdomain"`
	Name       string   `json:"service"`
	Vulnerable bool     `json:"vulnerable"`
}

func LoadFingerprints(customFile string) []Fingerprint {
	//var data Data
	var fingerprints []Fingerprint
	var fpData []byte
	if customFile != "" {
		// load fingerprints from user-provided file
		log.Info("Loading fingerprints from %s", customFile)
		content, err := os.ReadFile(customFile)
		if err != nil {
			log.Fatal("Unable to read %s: %v", customFile, err)
		}
		fpData = content
	} else {
		// load fingerprints from can-i-take-over-xyz
		log.Info("Loading fingerprints from can-i-take-over-xyz repository")
		resp, err := http.Get(FingerprintsUrl)
		if err != nil {
			log.Fatal("Unable to fetch fingerprints: %v", err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal("Unable to read fingerprints: %v", err)
		}
		fpData = body
	}
	err := json.Unmarshal(fpData, &fingerprints)
	if err != nil {
		log.Fatal("Unable to load services: %v", err)
	}
	return fingerprints
}
