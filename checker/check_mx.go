package checker

import (
	"fmt"

	"golang.org/x/net/publicsuffix"
)

// mxClassification decides how to report a dangling MX record, and whether
// claimability is unknown. Downgrading to a plain misconfiguration requires
// knowing the target domain cannot be registered; when the availability check
// itself failed the takeover classification stands, at low confidence, rather
// than a failed query quietly hiding a real finding.
func mxClassification(claimable bool, lookupErr error) (IssueType, ConfidenceLevel, bool) {
	switch {
	case lookupErr != nil:
		return IssueDanglingMx, ConfidenceLow, true
	case !claimable:
		return IssueDanglingUnclaimable, ConfidenceMedium, false
	default:
		return IssueDanglingMx, ConfidenceHigh, false
	}
}

// CheckMX checks if provided domain has dangling MX records
func (c *Checker) CheckMX(domain string) ([]*Match, error) {
	var findings []*Match

	// get MX records for the domain
	mxRecords, err := c.dns.GetMX(domain)
	if err != nil {
		c.verbose("%s: unable to get MX records: %v", domain, err)
		return nil, err
	}

	if len(mxRecords) == 0 {
		c.verbose("%s: no MX records found", domain)
		return findings, nil
	}

	// check each MX record for potential issues
	for _, mx := range mxRecords {
		c.verbose("%s: checking MX record: %s", domain, mx)

		// check if the MX hostname resolves
		mxResolutions := c.dns.Resolve(mx)
		if len(mxResolutions) == 0 {
			// MX hostname doesn't resolve, check if it's NXDOMAIN
			if c.dns.DomainIsNXDOMAIN(mx) {
				c.verbose("%s: MX record %s is NXDOMAIN", domain, mx)

				claimable, err := c.dns.DomainIsAvailable(mx)
				if err != nil {
					c.verbose("%s: could not establish whether MX %s is claimable: %v", domain, mx, err)
				}
				issue, confidence, unknown := mxClassification(claimable, err)
				reasons := []string{fmt.Sprintf("MX record %s is unregistered (NXDOMAIN)", mx)}
				switch {
				case unknown:
					reasons = append(reasons, "could not establish whether its domain is registerable")
				case issue == IssueDanglingUnclaimable:
					reasons = []string{fmt.Sprintf("MX record %s does not resolve, but its domain cannot be registered", mx)}
				}
				findings = append(findings, &Match{
					Domain:      domain,
					Target:      mx,
					Type:        issue,
					Method:      MethodNxdomain,
					Fingerprint: nil,
					Confidence:  confidence,
					Reasons:     reasons,
				})
				continue
			}
		}

		// check if the MX hostname is available for registration
		available, err := c.dns.DomainIsAvailable(mx)
		if err != nil {
			c.verbose("%s: error checking if MX %s is available: %v", domain, mx, err)
			continue
		}

		if available {
			c.verbose("%s: MX record %s is available for registration", domain, mx)

			finding := &Match{
				Domain:      domain,
				Target:      mx,
				Type:        IssueDanglingMx,
				Method:      MethodSoaCheck,
				Fingerprint: nil,
				Confidence:  ConfidenceHigh,
				Reasons:     []string{fmt.Sprintf("MX record %s is available for registration", mx)},
			}
			findings = append(findings, finding)
			continue
		}

		// check if the MX hostname has a valid SOA record
		soaRecords, err := c.dns.GetSOA(mx)
		if err != nil || len(soaRecords) == 0 {
			c.verbose("%s: MX record %s has no SOA record", domain, mx)

			// Try to get the root domain to check if it's properly configured
			rootDomain, err := publicsuffix.EffectiveTLDPlusOne(mx)
			if err != nil {
				c.verbose("%s: unable to determine root domain for MX %s: %v", domain, mx, err)
				continue
			}

			// Check if the root domain has proper DNS configuration
			rootSoaRecords, err := c.dns.GetSOA(rootDomain)
			if err != nil || len(rootSoaRecords) == 0 {
				c.verbose("%s: root domain %s for MX %s has no SOA record", domain, rootDomain, mx)

				finding := &Match{
					Domain:      domain,
					Target:      mx,
					Type:        IssueDanglingMx,
					Method:      MethodSoaCheck,
					Fingerprint: nil,
					Confidence:  ConfidenceMedium,
					Reasons:     []string{fmt.Sprintf("MX record %s has no SOA record and its root domain %s is misconfigured", mx, rootDomain)},
				}
				findings = append(findings, finding)
			}
		}
	}

	if len(findings) == 0 {
		c.verbose("%s: no dangling MX record found", domain)
	}
	return findings, nil
}
