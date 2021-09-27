package checks

import (
	_ "embed"
	"encoding/json"
	"log"
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

func LoadServices() []Service {
	var data Data
	err := json.Unmarshal(servicesData, &data)
	if err != nil {
		log.Fatalf("Unable to load services: %v", err)
	}
	return data.Services
}
