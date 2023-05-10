package checker

import (
	"github.com/mdeous/dnscheck/internal/log"
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

type CheckFunc func(string) ([]*Finding, error)

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
	checkFuncs   []CheckFunc
	findings     chan *Finding
	Domains      chan string
}

func (c *Checker) verbose(format string, values ...interface{}) {
	if c.cfg.Verbose {
		log.Debug(format, values...)
	}
}

func (c *Checker) scanWorker() {
	defer c.wg.Done()
	for domain := range c.Domains {
		log.Info("Checking %s", domain)
		for _, checkFunc := range c.checkFuncs {
			findings, err := checkFunc(domain)
			if err != nil {
				log.Warn(err.Error())
			} else {
				for _, finding := range findings {
					c.findings <- finding
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
	d.checkFuncs = []CheckFunc{
		d.CheckCNAME,
		d.CheckNS,
	}
	return d
}
