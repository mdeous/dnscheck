package checker

import (
	"fmt"
	"github.com/mdeous/dnscheck/dns"
	"github.com/mdeous/dnscheck/internal/utils"
	"strings"
)

func (c *Checker) checkPattern(domain string, pattern string) (bool, error) {
	c.verbose("%s: Performing HTTP request to '%s'", domain, domain)
	httpBody, err := utils.HttpGetBody(domain, c.cfg.HttpTimeout)
	if err != nil {
		c.verbose(err.Error())
		return false, err
	}
	return strings.Contains(httpBody, pattern), nil
}

func (c *Checker) checkFingerprint(domain string, fp *Fingerprint) (DetectionMethod, error) {
	if fp.NXDomain {
		if dns.DomainIsNXDOMAIN(domain, c.cfg.Nameserver) {
			return MethodCnameNxdomain, nil
		}

	} else if fp.HttpStatus != 0 {
		statusCode, err := utils.HttpGetStatus(domain, c.cfg.HttpTimeout)
		if err != nil {
			return MethodNone, fmt.Errorf("error while checking HTTP status code for %s: %v", domain, err)
		} else {
			if statusCode == fp.HttpStatus {
				return MethodCnameHttpStatus, nil
			}
		}

	} else if len(fp.Pattern) > 0 {
		patternMatches, err := c.checkPattern(domain, fp.Pattern)
		if err != nil {
			return MethodNone, fmt.Errorf("error while checking body fingerprint for %s: %v", domain, err)
		}
		if patternMatches {
			return MethodCnamePattern, nil
		}
	}
	return MethodNone, nil
}

// CheckCNAME checks if the CNAME entries for the provided domain are vulnerable
func (c *Checker) CheckCNAME(domain string) ([]*Match, error) {
	cnames, err := dns.GetCNAME(domain, c.cfg.Nameserver)
	if err != nil {
		return nil, err
	}
	var findings []*Match

	// target has CNAME records
	cnameMatch := false
	for _, cname := range cnames {
		c.verbose("%s: Found CNAME record: %s", domain, cname)
		// check if any fingerprint matches
		for _, fp := range c.fingerprints {
			for _, serviceCname := range fp.CNames {
				if strings.HasSuffix(cname, serviceCname) {
					c.verbose("%s: CNAME %s matches known service: %s", domain, cname, fp.Name)
					detectionMethod, err := c.checkFingerprint(domain, fp)
					if err != nil {
						continue
					}
					if detectionMethod != MethodNone {
						finding := &Match{
							Target:      cname,
							Type:        IssueDandlingCname,
							Method:      detectionMethod,
							Fingerprint: fp,
						}
						findings = append(findings, finding)
						cnameMatch = true
					}
				}
			}
		}

		// no fingerprint matched target domain, check if CNAME target can be registered
		c.verbose("%s: Checking CNAME target availability: %s", domain, cname)
		available, err := dns.DomainIsAvailable(cname, c.cfg.Nameserver)
		if err != nil {
			continue
		}
		if available {
			finding := &Match{
				Target:      cname,
				Type:        IssueUnregistered,
				Method:      MethodSoaCheck,
				Fingerprint: nil,
			}
			findings = append(findings, finding)
			cnameMatch = true
		}
	}

	// target has no CNAME records, check fingerprints that don't expect one
	resolveResults := dns.ResolveDomain(domain, c.cfg.Nameserver)
	if len(resolveResults) > 0 && !cnameMatch {
		c.verbose("%s: No CNAMEs but domain resolves, checking relevant fingerprints", domain)
		for _, fp := range c.fingerprints {
			if fp.Vulnerable && len(fp.CNames) == 0 {
				detectionMethod, err := c.checkFingerprint(domain, fp)
				if err != nil {
					continue
				}
				if detectionMethod != MethodNone {
					finding := &Match{
						Target:      strings.Join(resolveResults, ","),
						Type:        IssueDandlingCname,
						Method:      detectionMethod,
						Fingerprint: fp,
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	// no issue found
	c.verbose("%s: No possible takeover found", domain)
	return findings, nil
}
