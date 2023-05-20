package dns

import (
	"context"
	"net"
	"time"
)

func ResolveDomain(domain string, nameserver string) []string {
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
		return []string{}
	}
	return ips
}
