package dns

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
	"time"
)

var lookupErrors = []string{
	"no such host",
	"server misbehaving",
}

func GetCNAME(domain string, resolver string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeCNAME)
	ret, err := dns.Exchange(msg, resolver)
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

func DomainResolves(domain string, nameserver string) (bool, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(1000),
			}
			return d.DialContext(ctx, network, nameserver)
		},
	}
	ips, err := resolver.LookupHost(context.Background(), domain)
	if err != nil {
		for _, lookupErr := range lookupErrors {
			if strings.Contains(err.Error(), lookupErr) {
				return false, nil
			}
		}
		return false, fmt.Errorf("unexpected error while resolving %s: %v", domain, err)
	}
	return len(ips) > 0, nil
}
