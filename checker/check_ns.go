package checker

import "github.com/mdeous/dnscheck/dns"

// CheckNS checks if provided domain has dangling NS records
func (c *Checker) CheckNS(domain string) (*Finding, error) {
	if dns.DomainIsSERVFAIL(domain, c.cfg.Nameserver) {
		finding := &Finding{
			Domain:  domain,
			Target:  NoNameserver,
			Service: Unspecified,
			Type:    IssueNsTakeover,
		}
		return finding, nil
	}
	return nil, nil
}
