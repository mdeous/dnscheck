package dns

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
	"time"
)

const SERVFAIL = "server misbehaving"

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
	msg.SetQuestion(domain+".", dns.TypeNS)
	ret, err := dns.Exchange(msg, nameserver)
	if err != nil {
		return nil, fmt.Errorf("could not get CNAME for %s: %v", domain, err)
	}
	var records []string
	for _, answer := range ret.Answer {
		record, isNS := answer.(*dns.NS)
		if isNS {
			records = append(records, strings.TrimRight(record.Ns, "."))
		}
	}
	return records, nil
}

func DomainResolves(domain string, nameserver string) bool {
	resolver := makeResolver(nameserver)
	ips, err := resolver.LookupHost(context.Background(), domain)
	if err != nil {
		return false
	}
	return len(ips) > 0
}

func DomainIsSERVFAIL(domain string, nameserver string) bool {
	resolver := makeResolver(nameserver)
	_, err := resolver.LookupHost(context.Background(), domain)
	if err != nil {
		if strings.Contains(err.Error(), SERVFAIL) {
			return true
		}
	}
	return false
}
