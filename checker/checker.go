package checker

import (
	"github.com/mdeous/dnscheck/dns"
	"github.com/mdeous/dnscheck/log"
	"github.com/mdeous/dnscheck/utils"
	"strings"
	"sync"
)

type IssueType string

const (
	IssueTargetNoAuthority IssueType = "target might be registerable"
	IssueCnameTakeover               = "points to unclaimed resource"
	IssueNsTakeover                  = "unclaimed zone delegation"
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
	fingerprints []*Fingerprint
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

// checkPattern checks if the content of an HTTP GET request against provided domain
// matches the provided pattern.
func (c *Checker) checkPattern(domain string, pattern string) (bool, error) {
	c.verbose("%s: Performing HTTP request to '%s'", domain, domain)
	httpBody, err := utils.HttpGetBody(domain, c.cfg.HttpTimeout)
	if err != nil {
		c.verbose(err.Error())
		return false, err
	}
	return strings.Contains(httpBody, pattern), nil
}

func (c *Checker) checkFingerprint(domain string, fp *Fingerprint) (bool, error) {
	matchFound := false
	if fp.NXDomain {
		matchFound = dns.DomainIsNXDOMAIN(domain, c.cfg.Nameserver)

	} else if fp.HttpStatus != 0 {
		statusCode, err := utils.HttpGetStatus(domain, c.cfg.HttpTimeout)
		if err != nil {
			log.Warn("%s: Error while checking HTTP status code: %v", domain, err)
		} else {
			matchFound = statusCode == fp.HttpStatus
		}

	} else if len(fp.Pattern) > 0 {
		patternMatches, err := c.checkPattern(domain, fp.Pattern)
		if err != nil {
			return false, err
		}
		matchFound = patternMatches
	}
	return matchFound, nil
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

// CheckCNAME checks if the CNAME entries for the provided domain are vulnerable
func (c *Checker) CheckCNAME(domain string) (*Finding, error) {
	cnames, err := dns.GetCNAME(domain, c.cfg.Nameserver)
	if err != nil {
		return nil, err
	}

	// target has CNAME records
	for _, cname := range cnames {
		c.verbose("%s: Found CNAME record: %s", domain, cname)
		// check if any fingerprint matches
		for _, fp := range c.fingerprints {
			for _, serviceCname := range fp.CNames {
				if strings.HasSuffix(cname, serviceCname) {
					c.verbose("%s: CNAME %s matches known service: %s", domain, cname, fp.Name)
					vulnerable, err := c.checkFingerprint(domain, fp)
					if err != nil {
						continue
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
		}

		// no fingerprint matched target domain, check if CNAME target can be registered
		c.verbose("%s: Checking CNAME target availability: %s", domain, cname)
		available, err := dns.DomainIsAvailable(cname, c.cfg.Nameserver)
		if err != nil {
			continue
		}
		if available {
			finding := &Finding{
				Domain:      domain,
				Target:      cname,
				Service:     Unspecified,
				Type:        IssueTargetNoAuthority,
				Fingerprint: nil,
			}
			return finding, nil
		}
	}

	// target has no CNAME records, check fingerprints that don't expect one
	resolveResults := dns.ResolveDomain(domain, c.cfg.Nameserver)
	if len(resolveResults) > 0 {
		c.verbose("%s: No CNAMEs but domain resolves, checking relevant fingerprints", domain)
		for _, fp := range c.fingerprints {
			if fp.Vulnerable && len(fp.CNames) == 0 {
				vulnerable, err := c.checkFingerprint(domain, fp)
				if err != nil {
					continue
				}
				if vulnerable {
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

func (c *Checker) CheckNS(domain string) (*Finding, error) {
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

func NewChecker(config *Config) *Checker {
	d := &Checker{
		cfg:          config,
		fingerprints: LoadFingerprints(config.CustomFpFile),
		Domains:      make(chan string),
		findings:     make(chan *Finding),
	}
	d.checkFuncs = []func(string) (*Finding, error){
		d.CheckCNAME,
		d.CheckNS,
	}
	return d
}
