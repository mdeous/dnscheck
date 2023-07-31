package checker

import (
	"github.com/mdeous/dnscheck/dns"
	"github.com/mdeous/dnscheck/internal/log"
	"sync"
)

type CheckFunc func(string) ([]*Match, error)

type Config struct {
	Verbose        bool
	Workers        int
	CustomFpFile   string
	HttpTimeout    uint
	CheckEdgeCases bool
}

type Checker struct {
	cfg          *Config
	fingerprints []*Fingerprint
	wg           sync.WaitGroup
	checkFuncs   []CheckFunc
	findings     chan *DomainFinding
	Domains      chan string
	dns          *dns.Client
}

func (c *Checker) verbose(format string, values ...interface{}) {
	if c.cfg.Verbose {
		log.Debug(format, values...)
	}
}

func (c *Checker) scanWorker() {
	defer c.wg.Done()
	for domain := range c.Domains {
		result := &DomainFinding{
			Domain:  domain,
			Matches: make([]*Match, 0),
		}
		log.Info("Checking %s", domain)
		for _, checkFunc := range c.checkFuncs {
			findings, err := checkFunc(domain)
			if err != nil {
				log.Warn(err.Error())
			} else {
				for _, finding := range findings {
					result.Matches = append(result.Matches, finding)
				}
			}
		}
		c.findings <- result
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

func (c *Checker) Findings() <-chan *DomainFinding {
	return c.findings
}

func NewChecker(config *Config) *Checker {
	d := &Checker{
		cfg:          config,
		fingerprints: LoadFingerprints(config.CustomFpFile, config.CheckEdgeCases),
		Domains:      make(chan string),
		findings:     make(chan *DomainFinding),
		dns:          dns.NewClient(),
	}
	d.checkFuncs = []CheckFunc{
		d.CheckCNAME,
		d.CheckNS,
	}
	return d
}
