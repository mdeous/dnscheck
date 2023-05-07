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
		d.CheckCNAME,
		d.CheckNS,
	}
	return d
}
