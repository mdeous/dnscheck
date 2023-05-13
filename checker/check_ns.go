package checker

import "github.com/mdeous/dnscheck/dns"

// CheckNS checks if provided domain has dangling NS records
func (c *Checker) CheckNS(domain string) ([]*Match, error) {
	var findings []*Match
	if dns.DomainIsSERVFAIL(domain, c.cfg.Nameserver) {
		finding := &Match{
			Target:      "n/a",
			Type:        IssueDanglingNs,
			Method:      MethodServfail,
			Fingerprint: nil,
		}
		findings = append(findings, finding)
	}
	if len(findings) == 0 {
		c.verbose("%s: No dangling NS record found", domain)
	}
	return findings, nil
}
