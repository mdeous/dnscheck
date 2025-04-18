package checker

// CheckNS checks if provided domain has dangling NS records
func (c *Checker) CheckNS(domain string) ([]*Match, error) {
	var findings []*Match

	// get root domain
	rootDomain, err := c.dns.GetEffectiveTLDPlusOne(domain)
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

	allDangling := true
	partialDangling := false
	var failedNS []string
	var unregisteredNS []string

	// check if the nameservers themselves are registered
	for _, authority := range domainAuthorities {
		// check if the NS hostname itself resolves
		nsResolutions := c.dns.Resolve(authority)
		if len(nsResolutions) == 0 {
			// NS hostname doesn't resolve, check if it's NXDOMAIN
			if c.dns.DomainIsNXDOMAIN(authority) {
				c.verbose("%s: nameserver %s is NXDOMAIN", domain, authority)
				unregisteredNS = append(unregisteredNS, authority)
			}
		}
	}

	// if we found unregistered nameservers, report them
	if len(unregisteredNS) > 0 {
		finding := &Match{
			Domain:      domain,
			Target:      strings.Join(unregisteredNS, ","),
			Type:        IssueUnregisteredNs,
			Method:      MethodNxdomain,
			Fingerprint: nil,
		}
		findings = append(findings, finding)
	}

	// check if nameservers respond to queries
	for _, authority := range domainAuthorities {
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
		} else {
			// query A record
			aResp, errA := c.dns.Query(authorityAddr, domain, dns.TypeA)
			if errA == nil && aResp != nil && aResp.Rcode == dns.RcodeSuccess && len(aResp.Answer) > 0 {
				isDangling = false
			}

			// query AAAA record if still dangling
			if isDangling {
				aaaaResp, errAAAA := c.dns.Query(authorityAddr, domain, dns.TypeAAAA)
				if errAAAA == nil && aaaaResp != nil && aaaaResp.Rcode == dns.RcodeSuccess && len(aaaaResp.Answer) > 0 {
					isDangling = false
				}
			}
		}

		if isDangling {
			failedNS = append(failedNS, authority)
			continue
		}
		// if any NS responds, it's not fully dangling
		allDangling = false
		partialDangling = true
	}

	if allDangling {
		finding := &Match{
			Domain:      domain,
			Target:      strings.Join(domainAuthorities, ","),
			Type:        IssueDanglingNs,
			Method:      MethodServfail,
			Fingerprint: nil,
		}
		findings = append(findings, finding)
	} else if partialDangling && len(failedNS) > 0 {
		finding := &Match{
			Domain:      domain,
			Target:      strings.Join(failedNS, ","),
			Type:        IssuePartialDanglingNs,
			Method:      MethodServfail,
			Fingerprint: nil,
		}
		findings = append(findings, finding)
	}

	if len(findings) == 0 {
		c.verbose("%s: no dangling NS record found", domain)
	}
	return findings, nil
}
