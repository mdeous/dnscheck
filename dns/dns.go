package dns

import (
	"fmt"
	"github.com/mdeous/dnscheck/internal/log"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
	"strings"
)

type Client struct {
	cache *Cache
}

func (c *Client) query(nameserver string, domain string, reqType uint16) (*dns.Msg, error) {
	cachedResp := c.cache.Get(nameserver, domain, reqType)
	if cachedResp != nil {
		return cachedResp, nil
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), reqType)
	resp, err := dns.Exchange(msg, nameserver)
	if err != nil {
		return nil, err
	}
	c.cache.Put(nameserver, domain, reqType, resp)
	return resp, nil
}

func (c *Client) GetCNAME(domain string, nameserver string) ([]string, error) {
	ret, err := c.query(nameserver, domain, dns.TypeCNAME)
	if err != nil {
		return nil, fmt.Errorf("could not get CNAME for %s: %v", domain, err)
	}
	var records []string
	for _, answer := range ret.Answer {
		if record, isCNAME := answer.(*dns.CNAME); isCNAME {
			records = append(records, strings.TrimRight(record.Target, "."))
		}
	}
	return records, nil
}

func (c *Client) GetSOA(domain string, nameserver string) ([]string, error) {
	ret, err := c.query(nameserver, domain, dns.TypeSOA)
	if err != nil {
		return nil, fmt.Errorf("could not get CNAME for %s: %v", domain, err)
	}
	var records []string
	for _, answer := range ret.Answer {
		if record, isSOA := answer.(*dns.SOA); isSOA {
			records = append(records, strings.TrimRight(record.Ns, "."))
		}
	}
	return records, nil
}

func (c *Client) GetA(domain string, nameserver string) ([]string, error) {
	ret, err := c.query(nameserver, domain, dns.TypeA)
	if err != nil {
		return nil, fmt.Errorf("could not get A for %s: %v", domain, err)
	}
	var records []string
	for _, answer := range ret.Answer {
		if record, isA := answer.(*dns.A); isA {
			records = append(records, record.A.String())
		}
	}
	return records, nil
}

func (c *Client) GetAAAA(domain string, nameserver string) ([]string, error) {
	ret, err := c.query(nameserver, domain, dns.TypeAAAA)
	if err != nil {
		return nil, fmt.Errorf("could not get AAAA for %s: %v", domain, err)
	}
	var records []string
	for _, answer := range ret.Answer {
		if record, isAAAA := answer.(*dns.AAAA); isAAAA {
			records = append(records, record.AAAA.String())
		}
	}
	return records, nil
}

func (c *Client) GetNS(domain string, nameserver string) ([]string, error) {
	parseRecords := func(records []dns.RR) []string {
		var result []string
		for _, answer := range records {
			switch answer.(type) {
			case *dns.NS:
				result = append(result, answer.(*dns.NS).Ns)
			case *dns.SOA:
				result = append(result, answer.(*dns.SOA).Ns)
			}
		}
		return result
	}

	ret, err := c.query(nameserver, domain, dns.TypeNS)
	if err != nil {
		return nil, fmt.Errorf("could not get NS for %s: %v", domain, err)
	}
	var records []string
	if ret.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("could not get NS for %s: %v", domain, err)
	}
	if len(ret.Answer) > 0 {
		records = parseRecords(ret.Answer)
	} else {
		records = parseRecords(ret.Ns)
	}
	return records, nil
}

func (c *Client) DomainIsSERVFAIL(domain string, nameserver string) bool {
	rootDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		log.Warn("%s: unable to determine root domain: %v", domain, err)
		return false
	}

	rootNameservers, err := c.GetNS(rootDomain, nameserver)
	if err != nil {
		log.Warn("%s: unable to get nameserver: %v", domain, err)
		return false
	}
	if len(rootNameservers) == 0 {
		return false
	}

	domainAuthorities, err := c.GetNS(domain, rootNameservers[0]+":53")
	if err != nil {
		log.Warn("%s: unable to get authority for %s: %v", domain, domain, err)
		return false
	}

	for _, authority := range domainAuthorities {
		authority += ":53"
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		ret, err := dns.Exchange(msg, authority)
		if err != nil {
			continue
		}
		if ret.Rcode == dns.RcodeServerFailure || ret.Rcode == dns.RcodeRefused {
			return true
		}
	}
	return false
}

func (c *Client) DomainIsNXDOMAIN(domain string, nameserver string) bool {
	ret, err := c.query(nameserver, domain, dns.TypeA)
	if err != nil {
		log.Warn("%s: type A request to check NXDOMAIN failed: %v", domain, err)
		return false
	}
	return ret.Rcode == dns.RcodeNameError
}

func (c *Client) DomainIsAvailable(domain, nameserver string) (bool, error) {
	// extract root domain from CNAME target
	rootDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		log.Warn("Unable to get root domain for %s: %v", domain, err)
		return false, err
	}
	// check if domain resolves
	resolveResults := c.Resolve(rootDomain, nameserver)
	if err != nil {
		log.Warn("Error while resolving %s: %v", rootDomain, err)
		return false, err
	}
	if len(resolveResults) == 0 {
		// domain does not resolve, does it have an SOA record?
		soaRecords, err := c.GetSOA(rootDomain, nameserver)
		if err != nil {
			log.Warn("Error while querying SOA for %s: %v", rootDomain, err)
			return false, err
		}
		if len(soaRecords) == 0 {
			// CNAME target root domain has no SOA and does not resolve, might be available to registration
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) Resolve(domain string, nameserver string) []string {
	var resolutions []string
	aRecs, err := c.GetA(domain, nameserver)
	if err == nil {
		for _, a := range aRecs {
			resolutions = append(resolutions, a)
		}
	}
	aaaaRecs, err := c.GetAAAA(domain, nameserver)
	if err == nil {
		for _, aaaa := range aaaaRecs {
			resolutions = append(resolutions, aaaa)
		}
	}
	cnameRecs, err := c.GetCNAME(domain, nameserver)
	if err == nil {
		for _, cname := range cnameRecs {
			subResolutions := c.Resolve(cname, nameserver)
			for _, subResolution := range subResolutions {
				resolutions = append(resolutions, subResolution)
			}
		}
	}
	return resolutions
}

func NewClient() *Client {
	return &Client{
		cache: NewCache(),
	}
}
