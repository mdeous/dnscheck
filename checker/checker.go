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
	IssueTargetNoResolve IssueType = "target might be registerable"
	IssueCnameTakeover             = "points to unclaimed resource"
	IssueNsTakeover                = "unclaimed zone delegation"
)

const (
	Unspecified  = "n/a"
	NoNameserver = "no nameserver"
)

type Config struct {
	Nameserver   string
	Verbose      bool
	Workers      int
	CustomFpFile string
	HttpTimeout  uint
}

type Checker struct {
	cfg          *Config
	fingerprints []Fingerprint
	wg           sync.WaitGroup
	checkFuncs   []func(string) (*Finding, error)
	findings     chan *Finding
	Domains      chan string
}

func (c *Checker) verbose(format string, values ...interface{}) {
	if c.cfg.Verbose {
		log.Debug(format, values...)
	}
}

func (c *Checker) checkPattern(domain string, pattern string) (bool, error) {
	c.verbose("%s: Performing HTTP request to '%s'", domain, domain)
	httpBody, err := utils.HttpGetBody(domain, c.cfg.HttpTimeout)
	if err != nil {
		c.verbose(err.Error())
		return false, err
	}
	return strings.Contains(httpBody, pattern), nil
}

//func (c *Checker) checkAvailableDomain(domain string) (bool, error) {
//	return false, nil
//}

func (c *Checker) checkCNAME(domain string) (*Finding, error) {
	cnames, err := dns.GetCNAME(domain, c.cfg.Nameserver)
	if err != nil {
		return nil, err
	}

	if len(cnames) > 0 {
		// target has CNAME records
		c.verbose("%s: Found CNAME record: %s", domain, strings.Join(cnames, ", "))
		for _, cname := range cnames {
			// check if any fingerprint matches
			for _, fp := range c.fingerprints {
				for _, serviceCname := range fp.CNames {
					var vulnerable bool
					if strings.HasSuffix(cname, serviceCname) {
						c.verbose("%s: CNAME %s matches known service: %s", domain, cname, fp.Name)

						if fp.NXDomain {
							if dns.DomainIsNXDOMAIN(domain, c.cfg.Nameserver) {
								vulnerable = true
							}

						} else if fp.HttpStatus != 0 {
							statusCode, err := utils.HttpGetStatus(domain, c.cfg.HttpTimeout)
							if err != nil {
								log.Warn("%s: Error while checking HTTP status code: %v", domain, err)
							} else {
								if statusCode == fp.HttpStatus {
									vulnerable = true
								}
							}

						} else if len(fp.Pattern) > 0 {
							matchFound, err := c.checkPattern(domain, fp.Pattern)
							if err != nil {
								return nil, err
							}
							if matchFound {
								vulnerable = true
							}
						}

						if vulnerable {
							finding := &Finding{
								Domain:      domain,
								Target:      cname,
								Service:     fp.Name,
								Type:        IssueCnameTakeover,
								Fingerprint: fp,
							}
							return finding, nil
						}
					}
				}
				// TODO: check NXDOMAIN
				// TODO: check HTTP status code
			}

			// no fingerprint matched target domain

			c.verbose("%s: Checking CNAME target availability: %s", domain, cname)
			// extract root domain from CNAME target
			rootDomain, err := publicsuffix.EffectiveTLDPlusOne(cname)
			if err != nil {
				log.Warn("Unable to get root domain for %s: %v", cname, err)
				continue
			}
			// check if domain resolves
			resolveResults := dns.ResolveDomain(rootDomain, c.cfg.Nameserver)
			if err != nil {
				log.Warn("Error while resolving %s: %v", rootDomain, err)
				continue
			}
			if len(resolveResults) == 0 {
				// domain does not resolve, does it have an SOA record?
				soaRecords, err := dns.GetSOA(rootDomain, c.cfg.Nameserver)
				if err != nil {
					log.Warn("Error while querying SOA for %s: %v", rootDomain, err)
					continue
				}
				if len(soaRecords) == 0 {
					// CNAME target root domain has no SOA and does not resolve, might be available to registration
					finding := &Finding{
						Domain:  domain,
						Target:  rootDomain,
						Service: Unspecified,
						Type:    IssueTargetNoResolve,
					}
					return finding, nil
				}
			}
		}

	}

	// target has no CNAME records, check patterns for services that don't need one
	resolveResults := dns.ResolveDomain(domain, c.cfg.Nameserver)
	if len(resolveResults) > 0 {
		c.verbose("%s: No CNAMEs but domain resolves, checking known patterns", domain)
		for _, fp := range c.fingerprints {
			if fp.Vulnerable && len(fp.CNames) == 0 && len(fp.Pattern) > 0 {
				matchFound, err := c.checkPattern(domain, fp.Pattern)
				if err != nil {
					break
				}
				if matchFound {
					finding := &Finding{
						Domain:      domain,
						Target:      strings.Join(resolveResults, ","),
						Service:     fp.Name,
						Type:        IssueCnameTakeover,
						Fingerprint: fp,
					}
					return finding, nil
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
			Service: Unspecified,
			Type:    IssueNsTakeover,
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
					c.findings <- finding
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
		close(c.findings)
	}()
}

func (c *Checker) Findings() <-chan *Finding {
	return c.findings
}

func NewChecker(config *Config) *Checker {
	d := &Checker{
		cfg:          config,
		fingerprints: LoadFingerprints(config.CustomFpFile),
		Domains:      make(chan string),
		findings:     make(chan *Finding),
	}
	d.checkFuncs = []func(string) (*Finding, error){
		d.checkCNAME,
		d.checkNS,
	}
	return d
}
