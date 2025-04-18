package checker

// CheckNS checks if provided domain has dangling NS records
func (c *Checker) CheckNS(domain string) ([]*Match, error) {
	var findings []*Match

	// Get root domain
	rootDomain, err := c.dns.GetEffectiveTLDPlusOne(domain)
	if err != nil {
		c.verbose("%s: unable to determine root domain: %v", domain, err)
		return nil, err
	}
	// Get all root nameservers
	rootNameservers, err := c.dns.GetNS(rootDomain, c.dns.GetDefaultResolver())
	if err != nil || len(rootNameservers) == 0 {
		c.verbose("%s: unable to get root NS: %v", domain, err)
		return nil, err
	}
	// Get all authoritative NS for the domain
	domainAuthorities, err := c.dns.GetNS(domain, rootNameservers[0]+":53")
	if err != nil || len(domainAuthorities) == 0 {
		c.verbose("%s: unable to get authoritative NS: %v", domain, err)
		return nil, err
	}

	allDangling := true
	partialDangling := false
	var failedNS []string
	for _, authority := range domainAuthorities {
		authorityAddr := authority
		if !strings.Contains(authority, ":") {
			authorityAddr += ":53"
		}
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		ret, err := dns.Exchange(msg, authorityAddr)
		if err != nil || ret == nil || ret.Rcode == dns.RcodeServerFailure || ret.Rcode == dns.RcodeRefused {
			failedNS = append(failedNS, authority)
			continue
		}
		// If any NS responds without SERVFAIL/REFUSED, it's not fully dangling
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
