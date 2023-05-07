package checker

import (
	"github.com/mdeous/dnscheck/dns"
	"github.com/mdeous/dnscheck/log"
	"github.com/mdeous/dnscheck/utils"
	"golang.org/x/net/publicsuffix"
	"strings"
	"sync"
)

type IssueType string

const (
	IssueTargetNoResolve IssueType = "target might be unclaimed"
	IssueCnameTakeover             = "points to unclaimed resource"
	IssueNsTakeover                = "unclaimed zone delegation"
)

type DetectionMethod string

const (
	MethodCnameOnly    DetectionMethod = "CNAME only"
	MethodPatternOnly                  = "response body only"
	MethodCnamePattern                 = "CNAME + response body"
	MethodCnameLookup                  = "CNAME target lookup"
	MethodServfail                     = "SERVFAIL check"
)

const (
	NoService    = "n/a"
	NoTarget     = "no domain"
	NoNameserver = "no nameserver"
)

type Config struct {
	Nameserver   string
	Verbose      bool
	UseSSL       bool
	Workers      int
	CustomFpFile string
	HttpTimeout  uint
}

type Checker struct {
	cfg          *Config
	fingerprints []Fingerprint
	wg           sync.WaitGroup
	checkFuncs   []func(string) (*Finding, error)
	results      chan *Finding
	Domains      chan string
}

func (c *Checker) verbose(format string, values ...interface{}) {
	if c.cfg.Verbose {
		log.Debug(format, values...)
	}
}

func (c *Checker) checkPatterns(domain string, httpBody string, patterns []string) (*Finding, string, error) {
	var err error
	protocol := "http"
	if c.cfg.UseSSL {
		protocol += "s"
	}
	for _, pattern := range patterns {
		if httpBody == "" {
			url := protocol + "://" + domain
			c.verbose("%s: Fetching content of %s", domain, url)
			httpBody, err = utils.HttpGet(url, c.cfg.HttpTimeout)
			if err != nil {
				c.verbose(err.Error())
				return nil, "", err
			}
		}
		if strings.Contains(httpBody, pattern) {
			finding := &Finding{
				Domain: domain,
				Type:   IssueCnameTakeover,
			}
			return finding, httpBody, nil
		}
	}
	return nil, httpBody, nil
}

func (c *Checker) checkCNAME(domain string) (*Finding, error) {
	var (
		err            error
		httpBody       string
		finding        *Finding
		cnameHttpError bool
	)

	cnames, err := dns.GetCNAME(domain, c.cfg.Nameserver)
	if err != nil {
		return nil, err
	}

	var matchedServiceWithPatterns bool

	if len(cnames) > 0 {
		// target has CNAME records
		c.verbose("%s: Found CNAME record: %s", domain, strings.Join(cnames, ", "))
		for _, cname := range cnames {
			matchedServiceWithPatterns = false
			cnameHttpError = false
			for _, fp := range c.fingerprints {
				if len(fp.CNames) > 0 {
					for _, serviceCname := range fp.CNames {
						if strings.HasSuffix(cname, serviceCname) {
							c.verbose("%s: CNAME %s matches known service: %s", domain, cname, fp.Name)
							if len(fp.Patterns) > 0 {
								// CNAME record matches a known service for which we have signatures
								if !cnameHttpError {
									finding, httpBody, err = c.checkPatterns(domain, httpBody, fp.Patterns)
									if err != nil {
										cnameHttpError = true
									} else {
										if finding != nil {
											finding.Target = cname
											finding.Service = fp.Name
											finding.Method = MethodCnamePattern
											return finding, nil
										}
										matchedServiceWithPatterns = true
									}
								}
							} else {
								// CNAME matches a known service and we have no signatures to check
								finding = &Finding{
									Domain:  domain,
									Target:  cname,
									Service: fp.Name,
									Type:    IssueCnameTakeover,
									Method:  MethodCnameOnly,
								}
								return finding, nil
							}
						}
					}
				}
			}

			if !matchedServiceWithPatterns {
				c.verbose("%s: Checking CNAME target availability: %s", domain, cname)
				// extract root domain from CNAME target
				rootDomain, err := publicsuffix.EffectiveTLDPlusOne(cname)
				if err != nil {
					log.Warn("Unable to get root domain for %s: %v", cname, err)
					continue
				}
				// check if domain resolves
				rootResolves := dns.DomainResolves(rootDomain, c.cfg.Nameserver)
				if err != nil {
					log.Warn("Error while resolving %s: %v", rootDomain, err)
					continue
				}
				if !rootResolves {
					// domain does not resolve, does it have an SOA record?
					soaRecords, err := dns.GetSOA(rootDomain, c.cfg.Nameserver)
					if err != nil {
						log.Warn("Error while querying SOA for %s: %v", rootDomain, err)
						continue
					}
					if len(soaRecords) == 0 {
						// CNAME target root domain has no SOA and does not resolve, might be available to registration
						finding = &Finding{
							Domain:  domain,
							Target:  rootDomain,
							Service: NoService,
							Type:    IssueTargetNoResolve,
							Method:  MethodCnameLookup,
						}
						return finding, nil
					}
				}
			}
		}
	} else {
		// target has no CNAME records, check patterns for services that don't need one
		if dns.DomainResolves(domain, c.cfg.Nameserver) {
			c.verbose("%s: No CNAMEs but domain resolves, checking known patterns", domain)
			for _, service := range c.fingerprints {
				if len(service.CNames) == 0 {
					finding, httpBody, err = c.checkPatterns(domain, httpBody, service.Patterns)
					if err != nil {
						break
					}
					if finding != nil {
						finding.Target = NoTarget
						finding.Service = service.Name
						finding.Method = MethodPatternOnly
						return finding, nil
					}
				}
			}
		}
	}

	// no issue found
	c.verbose("%s: No possible takeover found", domain)
	return nil, nil
}

func (c *Checker) checkNS(domain string) (*Finding, error) {
	if dns.DomainIsSERVFAIL(domain, c.cfg.Nameserver) {
		finding := &Finding{
			Domain:  domain,
			Target:  NoNameserver,
			Service: NoService,
			Type:    IssueNsTakeover,
			Method:  MethodServfail,
		}
		return finding, nil
	}
	return nil, nil
}

func (c *Checker) scanWorker() {
	defer c.wg.Done()
	var (
		finding *Finding
		err     error
	)
	for domain := range c.Domains {
		log.Info("Checking %s", domain)
		for _, checkFunc := range c.checkFuncs {
			if finding, err = checkFunc(domain); err != nil {
				log.Warn(err.Error())
			} else {
				if finding != nil {
					c.results <- finding
					break
				}
			}
		}
	}
}

func (c *Checker) Scan() {
	// start workers
	for i := 1; i <= c.cfg.Workers; i++ {
		c.wg.Add(1)
		go c.scanWorker()
	}
	// wait for workers to finish and close results channel
	go func() {
		c.wg.Wait()
		close(c.results)
	}()
}

func (c *Checker) Results() <-chan *Finding {
	return c.results
}

func NewChecker(config *Config) *Checker {
	d := &Checker{
		cfg:          config,
		fingerprints: LoadFingerprints(config.CustomFpFile),
		Domains:      make(chan string),
		results:      make(chan *Finding),
	}
	d.checkFuncs = []func(string) (*Finding, error){
		d.checkCNAME,
		d.checkNS,
	}
	return d
}
