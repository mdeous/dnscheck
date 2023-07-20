package cmd

import (
	"github.com/mdeous/dnscheck/checker"
	"github.com/mdeous/dnscheck/internal/log"
	"github.com/mdeous/dnscheck/internal/utils"
	"github.com/spf13/cobra"
)

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Search for possible subdomain takeovers",
	Run: func(cmd *cobra.Command, args []string) {
		// get command-line arguments
		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			log.Fatal(err.Error())
		}
		fpFile, err := cmd.Flags().GetString("fingerprints")
		if err != nil {
			log.Fatal(err.Error())
		}
		singleDomain, err := cmd.Flags().GetString("domain")
		if err != nil {
			log.Fatal(err.Error())
		}
		domainFile, err := cmd.Flags().GetString("domains-file")
		if err != nil {
			log.Fatal(err.Error())
		}
		nameserver, err := cmd.Flags().GetString("nameserver")
		if err != nil {
			log.Fatal(err.Error())
		}
		workers, err := cmd.Flags().GetInt("workers")
		if err != nil {
			log.Fatal(err.Error())
		}
		output, err := cmd.Flags().GetString("output")
		if err != nil {
			log.Fatal(err.Error())
		}
		timeout, err := cmd.Flags().GetUint("timeout")
		if err != nil {
			log.Fatal(err.Error())
		}
		edgeCases, err := cmd.Flags().GetBool("edge-cases")
		if err != nil {
			log.Fatal(err.Error())
		}

		// instanciate domain checker
		chk := checker.NewChecker(&checker.Config{
			Nameserver:     nameserver,
			Verbose:        verbose,
			Workers:        workers,
			CustomFpFile:   fpFile,
			HttpTimeout:    timeout,
			CheckEdgeCases: edgeCases,
		})

		// load target domain(s)
		if singleDomain != "" {
			log.Info("Single domain mode (%s)", singleDomain)
			go func() {
				chk.Domains <- singleDomain
				close(chk.Domains)
			}()
		} else {
			log.Info("Multi domains mode (%s)", domainFile)
			go utils.ReadLines(domainFile, chk.Domains)
		}

		// scan domains and read results
		var findings []*checker.DomainFinding
		chk.Scan()
		for f := range chk.Findings() {
			for _, match := range f.Matches {
				fpName := "n/a"
				if match.Fingerprint != nil {
					fpName = match.Fingerprint.Name
				}
				log.Finding("[service: %s] %s -> %s [type=%s method=%s]", fpName, f.Domain, match.Target, match.Type, match.Method)
			}
			if len(f.Matches) > 0 && output != "" {
				findings = append(findings, f)
			}
		}

		// write results to file
		if output != "" {
			data := &checker.Findings{Data: findings}
			err := data.Write(output)
			if err != nil {
				log.Fatal("Unable to write results: %v", err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
	checkCmd.Flags().StringP("domain", "d", "", "single domain to check")
	checkCmd.Flags().StringP("domains-file", "D", "domains.txt", "file containing domains to check")
	checkCmd.Flags().StringP("nameserver", "n", "8.8.8.8:53", "server and port to use for name resolution")
	checkCmd.Flags().IntP("workers", "w", 10, "amount of concurrent workers")
	checkCmd.Flags().StringP("output", "o", "", "file to write findings to")
	checkCmd.Flags().UintP("timeout", "t", 10, "timeout for HTTP requests")
	checkCmd.Flags().BoolP("edge-cases", "e", false, "include edge-case fingerprints (might cause false positives)")
}
