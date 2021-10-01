package checks

import (
	_ "embed"
	"encoding/json"
	"github.com/mdeous/dnscheck/log"
	"io/ioutil"
)

//go:embed services.json
var servicesData []byte

type Service struct {
	Name     string   `json:"name"`
	CNames   []string `json:"cnames"`
	Patterns []string `json:"patterns"`
}

type Data struct {
	Services []Service `json:"services"`
}

func LoadServices(customFile string) []Service {
	var data Data
	if customFile != "" {
		log.Info("Loading fingerprints from %s", customFile)
		content, err := ioutil.ReadFile(customFile)
		if err != nil {
			log.Fatal("Unable to read %s: %v", customFile, err)
		}
		servicesData = content
	}
	err := json.Unmarshal(servicesData, &data)
	if err != nil {
		log.Fatal("Unable to load services: %v", err)
	}
	return data.Services
}
