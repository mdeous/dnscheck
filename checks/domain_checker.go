package checks

import (
	"github.com/mdeous/dnscheck/dns"
	"github.com/mdeous/dnscheck/log"
	"github.com/mdeous/dnscheck/utils"
	"golang.org/x/net/publicsuffix"
	"strings"
)

const NoService = "n/a"

type DomainCheckerConfig struct {
	Resolver string
	Verbose  bool
	UseSSL   bool
}

type DomainChecker struct {
	cfg      *DomainCheckerConfig
	services []Service
}

func (d *DomainChecker) verbose(format string, values ...interface{}) {
	if d.cfg.Verbose {
		log.Debug(format, values...)
	}
}

func (d *DomainChecker) checkPatterns(domain string, httpBody string, patterns []string) (*Finding, string) {
	var err error
	protocol := "http"
	if d.cfg.UseSSL {
		protocol += "s"
	}
	for _, pattern := range patterns {
		if httpBody == "" {
			url := protocol + "://" + domain
			d.verbose("Fetching content of %s", url)
			httpBody, err = utils.HttpGet(url)
			if err != nil {
				d.verbose(err.Error())
			}
		}
		if strings.Contains(httpBody, pattern) {
			finding := &Finding{
				Domain: domain,
				Type:   IssueCnameTakeover,
			}
			return finding, httpBody
		}
	}
	return nil, httpBody
}

func (d *DomainChecker) CheckCNAME(domain string) (*Finding, error) {
	var (
		err      error
		httpBody string
		finding  *Finding
	)

	cnames, err := dns.GetCNAME(domain, d.cfg.Resolver)
	if err != nil {
		return nil, err
	}

	resolves, err := dns.DomainResolves(domain, d.cfg.Resolver)
	if err != nil {
		return nil, err
	}

	var matchedServiceWithPatterns bool

	if len(cnames) > 0 {
		// target has CNAME records
		d.verbose("Found CNAME record for %s: %s", domain, strings.Join(cnames, ", "))
		for _, cname := range cnames {
			matchedServiceWithPatterns = false
			for _, service := range d.services {
				if len(service.CNames) > 0 {
					for _, serviceCname := range service.CNames {
						if strings.HasSuffix(cname, serviceCname) {
							d.verbose("CNAME %s matches known service: %s", cname, service.Name)
							if resolves && len(service.Patterns) > 0 {
								// CNAME record matches a known service for which we have signatures
								finding, httpBody = d.checkPatterns(domain, httpBody, service.Patterns)
								if finding != nil {
									finding.Target = cname
									finding.Service = service.Name
									finding.Method = MethodCnamePattern
									return finding, nil
								}
								matchedServiceWithPatterns = true
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
				d.verbose("Checking CNAME target domain")
				// extract root domain from CNAME target
				rootDomain, err := publicsuffix.EffectiveTLDPlusOne(cname)
				if err != nil {
					log.Warn("Unable to get root domain for %s: %v", cname, err)
					continue
				}
				// check if domain resolves
				resolves, err := dns.DomainResolves(rootDomain, d.cfg.Resolver)
				if err != nil {
					log.Warn("Error while resolving %s: %v", rootDomain, err)
					continue
				}
				if !resolves {
					// CNAME target root domain has no SOA, might be available to register
					finding := &Finding{
						Domain:  domain,
						Target:  cname,
						Service: NoService,
						Type:    IssueTargetNoResolve,
						Method:  MethodCnameLookup,
					}
					return finding, nil
				}
			}
		}
	} else {
		// target has no CNAME records, check patterns for services that don't need one
		if resolves {
			d.verbose("Target has no CNAMEs but resolves, checking against known patterns")
			for _, service := range d.services {
				if len(service.CNames) == 0 {
					finding, httpBody = d.checkPatterns(domain, httpBody, service.Patterns)
					if finding != nil {
						finding.Target = domain
						finding.Service = service.Name
						finding.Method = MethodPatternOnly
						return finding, nil
					}
				}
			}
		}
	}

	// no issue found
	d.verbose("No possible takeover found on %s", domain)
	return nil, nil
}

func (d *DomainChecker) CheckNS(_ string) (*Finding, error) {
	// TODO: implement dangling NS detection
	return nil, nil
}

func NewDomainChecker(config *DomainCheckerConfig) *DomainChecker {
	return &DomainChecker{
		cfg:      config,
		services: LoadServices(),
	}
}

