package dns

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// newTestResolver starts a DNS server on localhost that answers through the
// given handler, and returns its address. Each test drives it to reproduce the
// responses that used to be misread: REFUSED, a referral carrying NS records in
// the authority section, and a no-delegation reply carrying only an SOA.
func newTestResolver(t *testing.T, handler func(*dns.Msg) *dns.Msg) string {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}

	srv := &dns.Server{
		PacketConn: conn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			canned := handler(req)
			if canned == nil {
				return
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Rcode = canned.Rcode
			resp.Answer = canned.Answer
			resp.Ns = canned.Ns
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	return conn.LocalAddr().String()
}

// refusing answers every query with REFUSED, the way the OpenDNS addresses in
// the bundled resolver list do.
func refusing(t *testing.T) (addr string, queries *atomic.Int32) {
	t.Helper()
	var count atomic.Int32
	addr = newTestResolver(t, func(req *dns.Msg) *dns.Msg {
		count.Add(1)
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeRefused}}
	})
	return addr, &count
}

func newTestClient(addrs ...string) *Client {
	c := NewClient(2*time.Second, 0)
	c.Resolver.resolvers = addrs
	c.Resolver.current = 0
	c.Resolver.currentRequests = 0
	return c
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("could not build %q: %v", s, err)
	}
	return rr
}

// A resolver that will not answer tells us nothing about a domain. These tests
// pin down that such a reply is an error rather than an empty record set, which
// is what made dnscheck report registered domains as available.

func TestQueryRotateMovesPastARefusingResolver(t *testing.T) {
	bad, badQueries := refusing(t)
	good := newTestResolver(t, func(req *dns.Msg) *dns.Msg {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{mustRR(t, "takeover-target.com. 300 IN A 203.0.113.10")},
		}
	})

	records, err := newTestClient(bad, good).GetA("takeover-target.com")
	if err != nil {
		t.Fatalf("GetA() error = %v, want the second resolver to answer", err)
	}
	if len(records) != 1 || records[0] != "203.0.113.10" {
		t.Errorf("GetA() = %v, want [203.0.113.10]", records)
	}
	if badQueries.Load() == 0 {
		t.Error("expected the refusing resolver to be tried first")
	}
}

func TestQueryRotateErrorsWhenEveryResolverRefuses(t *testing.T) {
	first, _ := refusing(t)
	second, _ := refusing(t)

	if _, err := newTestClient(first, second).queryRotate("takeover-target.com", dns.TypeA); err == nil {
		t.Fatal("queryRotate() error = nil, want an error when no resolver answers")
	}
}

func TestGetSOAErrorsOnRefusedRatherThanReportingNoRecords(t *testing.T) {
	addr, _ := refusing(t)

	records, err := newTestClient(addr).GetSOA("takeover-target.com")
	if err == nil {
		t.Error("GetSOA() error = nil, want an error; a refusal is not proof there is no SOA")
	}
	if len(records) != 0 {
		t.Errorf("GetSOA() = %v, want no records", records)
	}
}

func TestDomainIsAvailableDoesNotReportAvailableWhenResolversRefuse(t *testing.T) {
	addr, _ := refusing(t)

	available, err := newTestClient(addr).DomainIsAvailable("sub.takeover-target.com")
	if available {
		t.Error("DomainIsAvailable() = true; a refusing resolver must not read as an unregistered domain")
	}
	if err == nil {
		t.Error("DomainIsAvailable() error = nil, want the failure surfaced to the caller")
	}
}

func TestDomainIsNXDOMAINIsFalseWhenRefused(t *testing.T) {
	addr, _ := refusing(t)

	if newTestClient(addr).DomainIsNXDOMAIN("takeover-target.com") {
		t.Error("DomainIsNXDOMAIN() = true; a refusal is not NXDOMAIN")
	}
}

func TestDomainIsNXDOMAINOnNameError(t *testing.T) {
	addr := newTestResolver(t, func(req *dns.Msg) *dns.Msg {
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	})

	if !newTestClient(addr).DomainIsNXDOMAIN("gone.takeover-target.com") {
		t.Error("DomainIsNXDOMAIN() = false, want true for NXDOMAIN")
	}
}

// A parent hands back a child's delegation as a referral, with the NS records
// in the authority section. A name with no delegation of its own gets only the
// parent's SOA there, and reading that SOA as a nameserver is what produced
// dangling-NS findings naming the zone's own nameserver.

func TestGetDelegationReadsNsFromTheAuthoritySection(t *testing.T) {
	addr := newTestResolver(t, func(req *dns.Msg) *dns.Msg {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Ns: []dns.RR{
				mustRR(t, "delegated.takeover-target.com. 300 IN NS ns1.elsewhere.com."),
				mustRR(t, "delegated.takeover-target.com. 300 IN NS ns2.elsewhere.com."),
			},
		}
	})

	records, err := newTestClient(addr).GetDelegation("delegated.takeover-target.com", addr)
	if err != nil {
		t.Fatalf("GetDelegation() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("GetDelegation() = %v, want both nameservers", records)
	}
}

func TestGetDelegationIgnoresAnSoaInTheAuthoritySection(t *testing.T) {
	addr := newTestResolver(t, func(req *dns.Msg) *dns.Msg {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Ns: []dns.RR{
				mustRR(t, "takeover-target.com. 1800 IN SOA ns1.takeover-target.com. hostmaster.takeover-target.com. 1 2 3 4 5"),
			},
		}
	})

	records, err := newTestClient(addr).GetDelegation("undelegated.takeover-target.com", addr)
	if err != nil {
		t.Fatalf("GetDelegation() error = %v", err)
	}
	if len(records) != 0 {
		t.Errorf("GetDelegation() = %v, want nothing; an SOA is not a delegation", records)
	}
}

func TestGetDelegationPrefersTheAnswerSection(t *testing.T) {
	addr := newTestResolver(t, func(req *dns.Msg) *dns.Msg {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{mustRR(t, "takeover-target.com. 300 IN NS ns1.takeover-target.com.")},
			Ns:     []dns.RR{mustRR(t, "takeover-target.com. 300 IN NS ns-stale.takeover-target.com.")},
		}
	})

	records, err := newTestClient(addr).GetDelegation("takeover-target.com", addr)
	if err != nil {
		t.Fatalf("GetDelegation() error = %v", err)
	}
	if len(records) != 1 || records[0] != "ns1.takeover-target.com." {
		t.Errorf("GetDelegation() = %v, want only the answer-section nameserver", records)
	}
}

// Reserved names resolve like anything else but can never be registered, so
// they must not be offered as takeover targets.

func TestIsReserved(t *testing.T) {
	reserved := []string{
		"example.com", "www.example.com", "example.net", "example.org",
		"anything.test", "anything.example", "anything.invalid",
		"localhost", "host.localhost", "printer.local", "service.onion",
		"EXAMPLE.COM", "trailing.example.com.",
	}
	for _, domain := range reserved {
		if !IsReserved(domain) {
			t.Errorf("IsReserved(%q) = false, want true", domain)
		}
	}

	registerable := []string{
		"takeover-target.com", "example.company.com", "notexample.com",
		"takeover-target.io", "sub.takeover-target.io", "localhost.com", "test.io",
	}
	for _, domain := range registerable {
		if IsReserved(domain) {
			t.Errorf("IsReserved(%q) = true, want false", domain)
		}
	}
}

func TestDomainIsAvailableShortCircuitsReservedNames(t *testing.T) {
	// this resolver would make any name look unregistered
	var queries atomic.Int32
	addr := newTestResolver(t, func(req *dns.Msg) *dns.Msg {
		queries.Add(1)
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	})

	available, err := newTestClient(addr).DomainIsAvailable("unclaimable.example.com")
	if err != nil {
		t.Fatalf("DomainIsAvailable() error = %v", err)
	}
	if available {
		t.Error("DomainIsAvailable() = true for a reserved name, want false")
	}
	if n := queries.Load(); n != 0 {
		t.Errorf("sent %d queries for a reserved name, want 0", n)
	}
}

// The rotation counters are shared by every scan worker. Run this with -race.

func TestResolverGetIsSafeForConcurrentUse(t *testing.T) {
	r := &Resolver{resolvers: []string{"192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53"}}

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 64 {
				if got := r.Get(); got == "" {
					t.Error("Get() returned an empty resolver")
				}
			}
		}()
	}
	wg.Wait()
}

func TestResolverNextAdvancesAndWraps(t *testing.T) {
	r := &Resolver{resolvers: []string{"192.0.2.1:53", "192.0.2.2:53"}}

	if got := r.Get(); got != "192.0.2.1:53" {
		t.Fatalf("Get() = %q, want the first resolver", got)
	}
	if got := r.Next(); got != "192.0.2.2:53" {
		t.Errorf("Next() = %q, want the second resolver", got)
	}
	if got := r.Next(); got != "192.0.2.1:53" {
		t.Errorf("Next() = %q, want to wrap to the first resolver", got)
	}
}

func TestResolverCountMatchesTheBundledList(t *testing.T) {
	r := NewResolver()
	if r.Count() == 0 {
		t.Fatal("Count() = 0, want the bundled resolvers to load")
	}
	for _, addr := range r.resolvers {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			t.Errorf("resolver %q is not a host:port address: %v", addr, err)
		}
	}
}

// Resolve must tell three outcomes apart: it resolved, it genuinely does not
// resolve, and the lookups failed so nothing is known. Collapsing the last two
// is what let a refusing resolver look like an absent record.

func TestResolveReturnsAddresses(t *testing.T) {
	addr := newTestResolver(t, func(req *dns.Msg) *dns.Msg {
		if req.Question[0].Qtype != dns.TypeA {
			return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}
		}
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{mustRR(t, "takeover-target.com. 300 IN A 203.0.113.10")},
		}
	})

	got, err := newTestClient(addr).Resolve("takeover-target.com")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(got) != 1 || got[0] != "203.0.113.10" {
		t.Errorf("Resolve() = %v, want [203.0.113.10]", got)
	}
}

func TestResolveIsEmptyWithoutErrorWhenNothingIsThere(t *testing.T) {
	addr := newTestResolver(t, func(req *dns.Msg) *dns.Msg {
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	})

	got, err := newTestClient(addr).Resolve("gone.takeover-target.com")
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil for a domain that simply does not resolve", err)
	}
	if len(got) != 0 {
		t.Errorf("Resolve() = %v, want nothing", got)
	}
}

func TestResolveErrorsWhenTheLookupsFail(t *testing.T) {
	addr, _ := refusing(t)

	got, err := newTestClient(addr).Resolve("takeover-target.com")
	if err == nil {
		t.Error("Resolve() error = nil; a refusing resolver must not read as a domain that does not resolve")
	}
	if len(got) != 0 {
		t.Errorf("Resolve() = %v, want nothing", got)
	}
}

func TestResolveSucceedsWhenOnlySomeLookupsFail(t *testing.T) {
	// A answers, AAAA and CNAME refuse: the domain demonstrably resolves, so
	// the partial failures do not matter
	addr := newTestResolver(t, func(req *dns.Msg) *dns.Msg {
		if req.Question[0].Qtype == dns.TypeA {
			return &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{mustRR(t, "takeover-target.com. 300 IN A 203.0.113.10")},
			}
		}
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeRefused}}
	})

	got, err := newTestClient(addr).Resolve("takeover-target.com")
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil when the domain resolved anyway", err)
	}
	if len(got) != 1 {
		t.Errorf("Resolve() = %v, want the one address that answered", got)
	}
}
