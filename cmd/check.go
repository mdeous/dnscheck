package cmd

import (
	"github.com/mdeous/dnscheck/checks"
	"github.com/mdeous/dnscheck/log"
	"github.com/mdeous/dnscheck/utils"
	"github.com/spf13/cobra"
)

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check for vulnerable domains",
	Run: func(cmd *cobra.Command, args []string) {
		// get command-line arguments
		domainFile, err := cmd.Flags().GetString("domains")
		if err != nil {
			log.Fatal(err.Error())
		}
		resolver, err := cmd.Flags().GetString("resolver")
		if err != nil {
			log.Fatal(err.Error())
		}
		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			log.Fatal(err.Error())
		}
		useSSL, err := cmd.Flags().GetBool("ssl")
		if err != nil {
			log.Fatal(err.Error())
		}

		// instanciate domain checker
		checker := checks.NewDomainChecker(&checks.DomainCheckerConfig{
			Resolver: resolver,
			Verbose:  verbose,
			UseSSL:   useSSL,
		})

		// load target domains
		domains := make(chan string)
		go utils.ReadLines(domainFile, domains)

		// check domains
		for domain := range domains {
			log.Info("Checking %s", domain)

			resultCNAME, err := checker.CheckCNAME(domain)
			if err != nil {
				log.Warn("Failed to check CNAME records for %s: %v", domain, err)
			} else {
				if resultCNAME != nil {
					log.Finding("[service: %s] %s %s: %s (method: %s)", resultCNAME.Service, resultCNAME.Domain, resultCNAME.Type, resultCNAME.Target, resultCNAME.Method)
				}
			}

			resultNS, err := checker.CheckNS(domain)
			if err != nil {
				log.Warn("Failed to check NS records for %s: %v", domain, err)
			} else {
				if resultNS != nil {
					log.Finding("[service: %s] %s %s: %s (method: %s)", resultNS.Service, resultNS.Domain, resultNS.Type, resultNS.Target, resultNS.Method)
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
	checkCmd.Flags().StringP("domains", "d", "", "file containing domains to check")
	err := checkCmd.MarkFlagRequired("domains")
	if err != nil {
		log.Fatal(err.Error())
	}
	checkCmd.Flags().StringP("resolver", "r", "8.8.8.8:53", "server and port to use for name resolution")
	checkCmd.Flags().BoolP("ssl", "S", false, "use HTTPS when connecting to targets")
}
