package dns

import (
	"context"
	"fmt"
	"github.com/mdeous/dnscheck/log"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
	"net"
	"strings"
	"time"
)

func makeResolver(nameserver string) *net.Resolver {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(1000),
			}
			return d.DialContext(ctx, network, nameserver)
		},
	}
	return resolver
}

func GetCNAME(domain string, nameserver string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeCNAME)
	ret, err := dns.Exchange(msg, nameserver)
	if err != nil {
		return nil, fmt.Errorf("could not get CNAME for %s: %v", domain, err)
	}
	var records []string
	for _, answer := range ret.Answer {
		record, isCNAME := answer.(*dns.CNAME)
		if isCNAME {
			records = append(records, strings.TrimRight(record.Target, "."))
		}
	}
	return records, nil
}

func GetSOA(domain string, nameserver string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeSOA)
	ret, err := dns.Exchange(msg, nameserver)
	if err != nil {
		return nil, fmt.Errorf("could not get CNAME for %s: %v", domain, err)
	}
	var records []string
	for _, answer := range ret.Answer {
		record, isSOA := answer.(*dns.SOA)
		if isSOA {
			records = append(records, strings.TrimRight(record.Ns, "."))
		}
	}
	return records, nil
}

func GetNS(domain string, nameserver string) ([]string, error) {
	parseRecords := func(records []dns.RR) []string {
		var result []string
		for _, answer := range records {
			nsRecord, isNS := answer.(*dns.NS)
			if isNS {
				result = append(result, nsRecord.Ns)
			} else {
				soaRecord, isSOA := answer.(*dns.SOA)
				if isSOA {
					result = append(result, soaRecord.Ns)
				}
			}
		}
		return result
	}

	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeNS)
	ret, err := dns.Exchange(msg, nameserver)
	if err != nil {
		return nil, fmt.Errorf("could not get NS for %s: %v", domain, err)
	}
	var records []string
	if ret.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("could not get NS for %s: %v", domain, err)
	}
	if len(ret.Answer) == 0 {
		records = parseRecords(ret.Answer)
	} else {
		records = parseRecords(ret.Ns)
	}
	return records, nil
}

func DomainIsSERVFAIL(domain string, nameserver string) bool {
	rootDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		log.Warn("%s: unable to determine root domain: %v", domain, err)
		return false
	}

	rootNameservers, err := GetNS(rootDomain, nameserver)
	if err != nil {
		log.Warn("%s: unable to get authority for %s: %v", domain, rootDomain, err)
		return false
	}
	if len(rootNameservers) == 0 {
		return false
	}

	domainAuthorities, err := GetNS(domain, rootNameservers[0])
	if err != nil {
		log.Warn("%s: unable to get authority for %s: %v", domain, domain, err)
		return false
	}

	for _, authority := range domainAuthorities {
		msg := new(dns.Msg)
		msg.SetQuestion(domain+".", dns.TypeA)
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

func DomainResolves(domain string, nameserver string) bool {
	resolver := makeResolver(nameserver)
	ips, err := resolver.LookupHost(context.Background(), domain)
	if err != nil {
		return false
	}
	return len(ips) > 0
}
