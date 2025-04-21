package checker

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// scoring system for dangling NS detection
type nsStatus struct {
	name             string
	unregistered     bool
	soaFailed        bool
	aFailed          bool
	aaaaFailed       bool
	danglingScore    int
	responseReceived bool
	failureReasons   []string
}

// CheckNS checks if provided domain has dangling NS records
func (c *Checker) CheckNS(domain string) ([]*Match, error) {
	var findings []*Match

	// get root domain
	rootDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		c.verbose("%s: unable to determine root domain: %v", domain, err)
		return nil, err
	}
	// get root nameservers
	rootNameservers, err := c.dns.GetNS(rootDomain, c.dns.Resolver.Get())
	if err != nil || len(rootNameservers) == 0 {
		c.verbose("%s: unable to get root NS: %v", domain, err)
		return nil, err
	}
	// get authoritative NS for the domain
	domainAuthorities, err := c.dns.GetNS(domain, rootNameservers[0]+":53")
	if err != nil || len(domainAuthorities) == 0 {
		c.verbose("%s: unable to get authoritative NS: %v", domain, err)
		return nil, err
	}

	var nsStatuses []nsStatus
	var failedNS []string
	var unregisteredNS []string

	// check if the nameservers themselves are registered
	for _, authority := range domainAuthorities {
		status := nsStatus{
			name:          authority,
			danglingScore: 0,
		}

		// check if the NS hostname itself resolves
		nsResolutions := c.dns.Resolve(authority)
		if len(nsResolutions) == 0 {
			// NS hostname doesn't resolve, check if it's NXDOMAIN
			if c.dns.DomainIsNXDOMAIN(authority) {
				c.verbose("%s: nameserver %s is NXDOMAIN", domain, authority)
				status.unregistered = true
				status.danglingScore += 3 // highest score for unregistered NS
				status.failureReasons = append(status.failureReasons, "unregistered")
				unregisteredNS = append(unregisteredNS, authority)
			}
		}

		nsStatuses = append(nsStatuses, status)
	}

	// if we found unregistered nameservers, report them
	if len(unregisteredNS) > 0 {
		var reasons []string
		for _, status := range nsStatuses {
			if status.unregistered {
				reasons = append(reasons, fmt.Sprintf("nameserver %s is unregistered (NXDOMAIN)", status.name))
			}
		}
		
		finding := &Match{
			Domain:      domain,
			Target:      strings.Join(unregisteredNS, ","),
			Type:        IssueUnregisteredNs,
			Method:      MethodNxdomain,
			Fingerprint: nil,
			Reason:      strings.Join(reasons, "; "),
			Confidence:  ConfidenceHigh, // unregistered NS is a high confidence finding
		}
		findings = append(findings, finding)
	}

	// check if nameservers respond to queries
	for i, authority := range domainAuthorities {
		authorityAddr := authority
		if !strings.Contains(authority, ":") {
			authorityAddr += ":53"
		}

		// query each NS for A, AAAA, and SOA records
		isDangling := true

		// query SOA record directly from this nameserver
		soaResp, errSOA := c.dns.Query(authorityAddr, domain, dns.TypeSOA)
		if errSOA == nil && soaResp != nil && soaResp.Rcode == dns.RcodeSuccess && len(soaResp.Answer) > 0 {
			// if we get a valid SOA response, the NS is definitely not dangling
			isDangling = false
			nsStatuses[i].responseReceived = true
		} else {
			nsStatuses[i].soaFailed = true
			nsStatuses[i].danglingScore += 2 // SOA failure is a strong indicator
			
			if errSOA != nil {
				nsStatuses[i].failureReasons = append(nsStatuses[i].failureReasons, 
					fmt.Sprintf("SOA query failed: %v", errSOA))
			} else if soaResp != nil {
				nsStatuses[i].failureReasons = append(nsStatuses[i].failureReasons, 
					fmt.Sprintf("SOA query returned %s with %d answers", 
						dns.RcodeToString[soaResp.Rcode], len(soaResp.Answer)))
			} else {
				nsStatuses[i].failureReasons = append(nsStatuses[i].failureReasons, "SOA query returned no response")
			}
			
			// query A record
			aResp, errA := c.dns.Query(authorityAddr, domain, dns.TypeA)
			if errA == nil && aResp != nil && aResp.Rcode == dns.RcodeSuccess && len(aResp.Answer) > 0 {
				isDangling = false
				nsStatuses[i].responseReceived = true
			} else {
				nsStatuses[i].aFailed = true
				nsStatuses[i].danglingScore += 1
				
				if errA != nil {
					nsStatuses[i].failureReasons = append(nsStatuses[i].failureReasons, 
						fmt.Sprintf("A query failed: %v", errA))
				} else if aResp != nil {
					nsStatuses[i].failureReasons = append(nsStatuses[i].failureReasons, 
						fmt.Sprintf("A query returned %s with %d answers", 
							dns.RcodeToString[aResp.Rcode], len(aResp.Answer)))
				} else {
					nsStatuses[i].failureReasons = append(nsStatuses[i].failureReasons, "A query returned no response")
				}
			}

			// query AAAA record if still dangling
			if isDangling {
				aaaaResp, errAAAA := c.dns.Query(authorityAddr, domain, dns.TypeAAAA)
				if errAAAA == nil && aaaaResp != nil && aaaaResp.Rcode == dns.RcodeSuccess && len(aaaaResp.Answer) > 0 {
					isDangling = false
					nsStatuses[i].responseReceived = true
				} else {
					nsStatuses[i].aaaaFailed = true
					nsStatuses[i].danglingScore += 1
					
					if errAAAA != nil {
						nsStatuses[i].failureReasons = append(nsStatuses[i].failureReasons, 
							fmt.Sprintf("AAAA query failed: %v", errAAAA))
					} else if aaaaResp != nil {
						nsStatuses[i].failureReasons = append(nsStatuses[i].failureReasons, 
							fmt.Sprintf("AAAA query returned %s with %d answers", 
								dns.RcodeToString[aaaaResp.Rcode], len(aaaaResp.Answer)))
					} else {
						nsStatuses[i].failureReasons = append(nsStatuses[i].failureReasons, "AAAA query returned no response")
					}
				}
			}
		}

		if isDangling {
			failedNS = append(failedNS, authority)
			continue
		}
	}

	// analyze results using the scoring system
	var highRiskNS []string
	var mediumRiskNS []string

	for _, status := range nsStatuses {
		if status.danglingScore >= 3 {
			// high risk: unregistered NS or multiple failures
			highRiskNS = append(highRiskNS, status.name)
		} else if status.danglingScore > 0 {
			// medium risk: some failures but not conclusive
			mediumRiskNS = append(mediumRiskNS, status.name)
		}
	}

	// report findings based on risk levels
	if len(highRiskNS) == len(domainAuthorities) {
		// all NS are high risk - definite dangling NS
		var reasons []string
		for _, status := range nsStatuses {
			if status.danglingScore >= 3 {
				nsInfo := fmt.Sprintf("nameserver %s: %s", status.name, strings.Join(status.failureReasons, ", "))
				reasons = append(reasons, nsInfo)
			}
		}
		
		finding := &Match{
			Domain:      domain,
			Target:      strings.Join(highRiskNS, ","),
			Type:        IssueDanglingNs,
			Method:      MethodServfail,
			Fingerprint: nil,
			Confidence:  ConfidenceHigh,
			Reason:      strings.Join(reasons, "; "),
		}
		findings = append(findings, finding)
	} else if len(highRiskNS) > 0 {
		// some NS are high risk - partial dangling NS
		var reasons []string
		for _, status := range nsStatuses {
			if status.danglingScore >= 3 {
				nsInfo := fmt.Sprintf("nameserver %s: %s", status.name, strings.Join(status.failureReasons, ", "))
				reasons = append(reasons, nsInfo)
			}
		}
		
		finding := &Match{
			Domain:      domain,
			Target:      strings.Join(highRiskNS, ","),
			Type:        IssuePartialDanglingNs,
			Method:      MethodServfail,
			Fingerprint: nil,
			Confidence:  ConfidenceMedium,
			Reason:      strings.Join(reasons, "; "),
		}
		findings = append(findings, finding)
	} else if len(mediumRiskNS) > 0 && len(mediumRiskNS) == len(domainAuthorities) {
		// all NS are medium risk - likely dangling NS
		var reasons []string
		for _, status := range nsStatuses {
			if status.danglingScore > 0 && status.danglingScore < 3 {
				nsInfo := fmt.Sprintf("nameserver %s: %s", status.name, strings.Join(status.failureReasons, ", "))
				reasons = append(reasons, nsInfo)
			}
		}
		
		finding := &Match{
			Domain:      domain,
			Target:      strings.Join(mediumRiskNS, ","),
			Type:        IssueDanglingNs,
			Method:      MethodServfail,
			Fingerprint: nil,
			Confidence:  ConfidenceLow,
			Reason:      strings.Join(reasons, "; "),
		}
		findings = append(findings, finding)
	}

	if len(findings) == 0 {
		c.verbose("%s: no dangling NS record found", domain)
	}
	return findings, nil
}
