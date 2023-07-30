package checker

import (
	"fmt"
	"github.com/mdeous/dnscheck/dns"
	"github.com/mdeous/dnscheck/internal/utils"
	"strings"
)

func (c *Checker) checkPattern(domain string, pattern string, body string) (bool, string, error) {
	var err error
	if body == "" {
		c.verbose("%s: Performing HTTP request to '%s'", domain, domain)
		body, err = utils.HttpGetBody(domain, c.cfg.HttpTimeout)
		if err != nil {
			c.verbose(err.Error())
			return false, "", err
		}
	}

	return strings.Contains(body, pattern), body, nil
}

func (c *Checker) checkFingerprint(domain string, fp *Fingerprint, body string, hasCname bool) (DetectionMethod, string, error) {
	var err error
	if fp.NXDomain {
		if c.dns.DomainIsNXDOMAIN(domain, c.cfg.Nameserver) {
			if hasCname {
				return MethodCnameNxdomain, body, nil
			}
			return MethodNxdomain, body, nil
		}

	} else if fp.HasHttpStatus() {
		statusCode, err := utils.HttpGetStatus(domain, c.cfg.HttpTimeout)
		if err != nil {
			return MethodNone, body, fmt.Errorf("error while checking HTTP status code for %s: %v", domain, err)
		} else {
			if statusCode == fp.HttpStatus {
				if hasCname {
					return MethodCnameHttpStatus, body, nil
				}
				return MethodHttpStatus, body, nil
			}
		}

	} else if fp.HasPattern() {
		var patternMatches bool
		patternMatches, body, err = c.checkPattern(domain, fp.Pattern, body)
		if err != nil {
			return MethodNone, body, fmt.Errorf("error while checking body fingerprint for %s: %v", domain, err)
		}
		if patternMatches {
			if hasCname {
				return MethodCnamePattern, body, nil
			}
			return MethodPattern, body, nil
		}
	}
	return MethodNone, body, nil
}

// CheckCNAME checks if the CNAME entries for the provided domain are vulnerable
func (c *Checker) CheckCNAME(domain string) ([]*Match, error) {
	var err error
	cnames, err := c.dns.GetCNAME(domain, c.cfg.Nameserver)
	if err != nil {
		return nil, err
	}
	var findings []*Match
	var detectionMethod DetectionMethod

	// target has CNAME records
	body := ""
	for _, cname := range cnames {
		c.verbose("%s: Found CNAME record: %s", domain, cname)
		// check if any fingerprint matches
		for _, fp := range c.fingerprints {
			for _, serviceCname := range fp.CNames {
				if strings.HasSuffix(cname, serviceCname) {
					c.verbose("%s: CNAME %s matches known service: %s", domain, cname, fp.Name)
					detectionMethod, body, err = c.checkFingerprint(domain, fp, body, true)
					if err != nil {
						continue
					}
					if detectionMethod != MethodNone {
						finding := &Match{
							Domain:      domain,
							Target:      cname,
							Type:        IssueDandlingCname,
							Method:      detectionMethod,
							Fingerprint: fp,
						}
						findings = append(findings, finding)
					}
				}
			}
		}

		if len(findings) == 0 {
			// no fingerprint matched target domain, check if CNAME target can be registered
			c.verbose("%s: Checking CNAME target availability: %s", domain, cname)
			available, err := c.dns.DomainIsAvailable(cname, c.cfg.Nameserver)
			if err != nil {
				continue
			}
			if available {
				finding := &Match{
					Domain:      domain,
					Target:      cname,
					Type:        IssueUnregistered,
					Method:      MethodSoaCheck,
					Fingerprint: nil,
				}
				findings = append(findings, finding)
			}
		}
	}

	// target has no CNAME records, check fingerprints that don't expect one
	resolveResults := dns.ResolveDomain(domain, c.cfg.Nameserver)
	if len(findings) == 0 && len(resolveResults) > 0 {
		c.verbose("%s: No CNAMEs but domain resolves, checking relevant fingerprints", domain)
		for _, fp := range c.fingerprints {
			if !fp.HasCNames() {
				detectionMethod, body, err = c.checkFingerprint(domain, fp, body, false)
				if err != nil {
					continue
				}
				if detectionMethod != MethodNone {
					finding := &Match{
						Domain:      domain,
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

	if len(findings) == 0 {
		c.verbose("%s: No dangling CNAME record found", domain)
	}
	return findings, nil
}
