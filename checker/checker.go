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
	cfg        *Config
	services   []Service
	wg         sync.WaitGroup
	checkFuncs []func(string) (*Finding, error)
	results    chan *Finding
	Domains    chan string
}

func (d *Checker) verbose(format string, values ...interface{}) {
	if d.cfg.Verbose {
		log.Debug(format, values...)
	}
}

func (d *Checker) checkPatterns(domain string, httpBody string, patterns []string) (*Finding, string, error) {
	var err error
	protocol := "http"
	if d.cfg.UseSSL {
		protocol += "s"
	}
	for _, pattern := range patterns {
		if httpBody == "" {
			url := protocol + "://" + domain
			d.verbose("%s: Fetching content of %s", domain, url)
			httpBody, err = utils.HttpGet(url, d.cfg.HttpTimeout)
			if err != nil {
				d.verbose(err.Error())
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

func (d *Checker) checkCNAME(domain string) (*Finding, error) {
	var (
		err            error
		httpBody       string
		finding        *Finding
		cnameHttpError bool
	)

	cnames, err := dns.GetCNAME(domain, d.cfg.Nameserver)
	if err != nil {
		return nil, err
	}

	resolves := dns.DomainResolves(domain, d.cfg.Nameserver)

	var matchedServiceWithPatterns bool

	if len(cnames) > 0 {
		// target has CNAME records
		d.verbose("%s: Found CNAME record: %s", domain, strings.Join(cnames, ", "))
		for _, cname := range cnames {
			matchedServiceWithPatterns = false
			cnameHttpError = false
			for _, service := range d.services {
				if len(service.CNames) > 0 {
					for _, serviceCname := range service.CNames {
						if strings.HasSuffix(cname, serviceCname) {
							d.verbose("%s: CNAME %s matches known service: %s", domain, cname, service.Name)
							if resolves && len(service.Patterns) > 0 {
								// CNAME record matches a known service for which we have signatures
								if !cnameHttpError {
									finding, httpBody, err = d.checkPatterns(domain, httpBody, service.Patterns)
									if err != nil {
										cnameHttpError = true
									} else {
										if finding != nil {
											finding.Target = cname
											finding.Service = service.Name
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
									Service: service.Name,
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
				d.verbose("%s: Checking CNAME target availability: %s", domain, cname)
				// extract root domain from CNAME target
				rootDomain, err := publicsuffix.EffectiveTLDPlusOne(cname)
				if err != nil {
					log.Warn("Unable to get root domain for %s: %v", cname, err)
					continue
				}
				// check if domain resolves
				rootResolves := dns.DomainResolves(rootDomain, d.cfg.Nameserver)
				if err != nil {
					log.Warn("Error while resolving %s: %v", rootDomain, err)
					continue
				}
				if !rootResolves {
					// domain does not resolve, does it have an SOA record?
					soaRecords, err := dns.GetSOA(rootDomain, d.cfg.Nameserver)
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
		if resolves {
			d.verbose("%s: No CNAMEs but domain resolves, checking known patterns", domain)
			for _, service := range d.services {
				if len(service.CNames) == 0 {
					finding, httpBody, err = d.checkPatterns(domain, httpBody, service.Patterns)
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
	d.verbose("%s: No possible takeover found", domain)
	return nil, nil
}

func (d *Checker) checkNS(domain string) (*Finding, error) {
	if dns.DomainIsSERVFAIL(domain, d.cfg.Nameserver) {
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

func (d *Checker) scanWorker() {
	defer d.wg.Done()
	var (
		finding *Finding
		err     error
	)
	for domain := range d.Domains {
		log.Info("Checking %s", domain)
		for _, checkFunc := range d.checkFuncs {
			if finding, err = checkFunc(domain); err != nil {
				log.Warn(err.Error())
			} else {
				if finding != nil {
					d.results <- finding
					break
				}
			}
		}
	}
}

func (d *Checker) Scan() {
	// start workers
	for i := 1; i <= d.cfg.Workers; i++ {
		d.wg.Add(1)
		go d.scanWorker()
	}
	// wait for workers to finish and close results channel
	go func() {
		d.wg.Wait()
		close(d.results)
	}()
}

func (d *Checker) Results() <-chan *Finding {
	return d.results
}

func NewChecker(config *Config) *Checker {
	d := &Checker{
		cfg:      config,
		services: LoadServices(config.CustomFpFile),
		Domains:  make(chan string),
		results:  make(chan *Finding),
	}
	d.checkFuncs = []func(string) (*Finding, error){
		d.checkCNAME,
		d.checkNS,
	}
	return d
}
