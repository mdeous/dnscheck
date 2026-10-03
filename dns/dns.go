package dns

import (
	"errors"
	"fmt"
	"github.com/mdeous/dnscheck/internal/log"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
	"net"
	"strings"
	"time"
)

const retryBackoff = 100 * time.Millisecond

type Client struct {
	cache    *Cache
	Resolver *Resolver
	client   *dns.Client
	retries  int
}

// exchange performs a DNS exchange with retry on timeout errors.
func (c *Client) exchange(msg *dns.Msg, nameserver string) (*dns.Msg, error) {
	attempts := c.retries + 1
	var lastErr error
	for i := range attempts {
		resp, _, err := c.client.Exchange(msg, nameserver)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			return nil, err
		}
		if i < attempts-1 {
			log.Debug("DNS query to %s timed out (attempt %d/%d), retrying", nameserver, i+1, attempts)
			time.Sleep(retryBackoff)
		}
	}
	return nil, lastErr
}

// queryRotate queries domain, moving to another resolver when one refuses or
// fails outright. A REFUSED or SERVFAIL answer means "no usable reply", never
// "no such record", so it must not be read as an empty answer set.
func (c *Client) queryRotate(domain string, reqType uint16) (*dns.Msg, error) {
	nameserver := c.Resolver.Get()
	var lastErr error
	for range c.Resolver.Count() {
		ret, err := c.Query(nameserver, domain, reqType)
		if err == nil {
			if ret.Rcode == dns.RcodeSuccess || ret.Rcode == dns.RcodeNameError {
				return ret, nil
			}
			lastErr = fmt.Errorf("%s answered %s", nameserver, dns.RcodeToString[ret.Rcode])
		} else {
			lastErr = err
		}
		nameserver = c.Resolver.Next()
	}
	return nil, fmt.Errorf("no resolver could answer %s: %v", domain, lastErr)
}

// Query performs a DNS query using the specified nameserver
func (c *Client) Query(nameserver string, domain string, reqType uint16) (*dns.Msg, error) {
	cachedResp := c.cache.Get(nameserver, domain, reqType)
	if cachedResp != nil {
		return cachedResp, nil
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), reqType)
	resp, err := c.exchange(msg, nameserver)
	if err != nil {
		return nil, err
	}
	c.cache.Put(nameserver, domain, reqType, resp)
	return resp, nil
}

func (c *Client) GetCNAME(domain string) ([]string, error) {
	ret, err := c.queryRotate(domain, dns.TypeCNAME)
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

func (c *Client) GetSOA(domain string) ([]string, error) {
	ret, err := c.queryRotate(domain, dns.TypeSOA)
	if err != nil {
		return nil, fmt.Errorf("could not get SOA for %s: %v", domain, err)
	}
	var records []string
	for _, answer := range ret.Answer {
		if record, isSOA := answer.(*dns.SOA); isSOA {
			records = append(records, strings.TrimRight(record.Ns, "."))
		}
	}
	return records, nil
}

func (c *Client) GetA(domain string) ([]string, error) {
	ret, err := c.queryRotate(domain, dns.TypeA)
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

func (c *Client) GetAAAA(domain string) ([]string, error) {
	ret, err := c.queryRotate(domain, dns.TypeAAAA)
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

	ret, err := c.Query(nameserver, domain, dns.TypeNS)
	if err != nil {
		return nil, fmt.Errorf("could not get NS for %s: %v", domain, err)
	}
	var records []string
	if ret.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("could not get NS for %s: %s", domain, dns.RcodeToString[ret.Rcode])
	}
	if len(ret.Answer) > 0 {
		records = parseRecords(ret.Answer)
	} else {
		records = parseRecords(ret.Ns)
	}
	return records, nil
}

// GetDelegation returns the nameservers a domain is actually delegated to, and
// nothing else. GetNS also accepts an SOA as a nameserver, so a name with no
// delegation of its own yields the parent zone's SOA MNAME and then looks
// dangling; the delegation check needs NS records or nothing.
func (c *Client) GetDelegation(domain string, nameserver string) ([]string, error) {
	ret, err := c.Query(nameserver, domain, dns.TypeNS)
	if err != nil {
		return nil, fmt.Errorf("could not get delegation for %s: %v", domain, err)
	}
	if ret.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("could not get delegation for %s: %s", domain, dns.RcodeToString[ret.Rcode])
	}
	// a parent returns a child's delegation as a referral, so the NS records
	// arrive in the authority section; only the apex answers in-section.
	var records []string
	for _, rrs := range [][]dns.RR{ret.Answer, ret.Ns} {
		for _, answer := range rrs {
			if record, isNS := answer.(*dns.NS); isNS {
				records = append(records, record.Ns)
			}
		}
		if len(records) > 0 {
			break
		}
	}
	return records, nil
}

func (c *Client) GetMX(domain string) ([]string, error) {
	ret, err := c.queryRotate(domain, dns.TypeMX)
	if err != nil {
		return nil, fmt.Errorf("could not get MX for %s: %v", domain, err)
	}
	var records []string
	for _, answer := range ret.Answer {
		if record, isMX := answer.(*dns.MX); isMX {
			records = append(records, strings.TrimRight(record.Mx, "."))
		}
	}
	return records, nil
}

// GetRootNS looks up a domain's nameservers via the public resolvers, moving on
// when one refuses rather than reporting "no nameservers".
func (c *Client) GetRootNS(domain string) ([]string, error) {
	nameserver := c.Resolver.Get()
	var lastErr error
	for range c.Resolver.Count() {
		records, err := c.GetNS(domain, nameserver)
		if err == nil && len(records) > 0 {
			return records, nil
		}
		if err != nil {
			lastErr = err
		}
		nameserver = c.Resolver.Next()
	}
	return nil, fmt.Errorf("no resolver could answer NS for %s: %v", domain, lastErr)
}

func (c *Client) DomainIsSERVFAIL(domain string) bool {
	rootDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		log.Warn("%s: unable to determine root domain: %v", domain, err)
		return false
	}

	rootNameservers, err := c.GetRootNS(rootDomain)
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
		ret, err := c.exchange(msg, authority)
		if err != nil {
			continue
		}
		if ret.Rcode == dns.RcodeServerFailure || ret.Rcode == dns.RcodeRefused {
			return true
		}
	}
	return false
}

func (c *Client) DomainIsNXDOMAIN(domain string) bool {
	ret, err := c.queryRotate(domain, dns.TypeA)
	if err != nil {
		log.Warn("%s: type A request to check NXDOMAIN failed: %v", domain, err)
		return false
	}
	return ret.Rcode == dns.RcodeNameError
}

// reservedTLDs and reservedDomains can never be registered by anyone: RFC 2606
// (.test/.example/.invalid/.localhost, example.com/net/org) and RFC 6761.
var reservedTLDs = []string{"test", "example", "invalid", "localhost", "local", "onion"}

var reservedDomains = []string{"example.com", "example.net", "example.org"}

// IsReserved reports whether a name sits under a special-use TLD or domain, and
// so is not available to register however it resolves.
func IsReserved(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, d := range reservedDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	for _, tld := range reservedTLDs {
		if domain == tld || strings.HasSuffix(domain, "."+tld) {
			return true
		}
	}
	return false
}

func (c *Client) DomainIsAvailable(domain string) (bool, error) {
	// reserved names resolve like anything else but cannot be registered
	if IsReserved(domain) {
		return false, nil
	}
	// extract root domain from CNAME target
	rootDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		log.Warn("Unable to get root domain for %s: %v", domain, err)
		return false, err
	}
	// check if domain resolves
	resolveResults := c.Resolve(rootDomain)
	if err != nil {
		log.Warn("Error while resolving %s: %v", rootDomain, err)
		return false, err
	}
	if len(resolveResults) == 0 {
		// domain does not resolve, does it have an SOA record?
		soaRecords, err := c.GetSOA(rootDomain)
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

func (c *Client) Resolve(domain string) []string {
	var resolutions []string
	aRecs, err := c.GetA(domain)
	if err == nil {
		for _, a := range aRecs {
			resolutions = append(resolutions, a)
		}
	}
	aaaaRecs, err := c.GetAAAA(domain)
	if err == nil {
		for _, aaaa := range aaaaRecs {
			resolutions = append(resolutions, aaaa)
		}
	}
	cnameRecs, err := c.GetCNAME(domain)
	if err == nil {
		for _, cname := range cnameRecs {
			subResolutions := c.Resolve(cname)
			for _, subResolution := range subResolutions {
				resolutions = append(resolutions, subResolution)
			}
		}
	}
	return resolutions
}

func NewClient(timeout time.Duration, retries int) *Client {
	return &Client{
		cache:    NewCache(),
		Resolver: NewResolver(),
		client:   &dns.Client{Timeout: timeout},
		retries:  retries,
	}
}
