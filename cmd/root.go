package cmd

import (
	"fmt"
	"github.com/mdeous/dnscheck/checker"
	"github.com/mdeous/dnscheck/internal/log"
	"github.com/mdeous/dnscheck/internal/utils"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "dnscheck",
	Short: "Subdomain takeover assessment tool",
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
		skipSummary, err := cmd.Flags().GetBool("skip-summary")
		if err != nil {
			log.Fatal(err.Error())
		}

		// instanciate domain checker
		chk := checker.NewChecker(&checker.Config{
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

		// display status for edge-case rules
		if edgeCases {
			log.Info("Edge-case rules enabled")
		}

		// scan domains and read results
		var findings []*checker.DomainFinding
		fCount := 0
		mCount := 0
		chk.Scan()
		for f := range chk.Findings() {
			for _, match := range f.Matches {
				log.Finding(match.String())
			}
			if len(f.Matches) > 0 {
				findings = append(findings, f)
				fCount++
				mCount += len(f.Matches)
			}
		}
		log.Info("Scan complete")

		// display results summary
		if !skipSummary && singleDomain == "" {
			summary := fmt.Sprintf("Vulnerable domains: %d", fCount)
			if mCount > 0 {
				summary += fmt.Sprintf(" (%d service matches)", mCount)
			}
			log.Info(summary)
			for _, f := range findings {
				for _, match := range f.Matches {
					log.Finding(match.String())
				}
			}
		}

		// write results to file
		if output != "" {
			data := &checker.Findings{Data: findings}
			err := data.Write(output)
			if err != nil {
				log.Fatal("Unable to write results: %v", err)
			} else {
				log.Info("Results written to %s", output)
			}
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.Flags().StringP("domain", "d", "", "single domain to check")
	rootCmd.Flags().StringP("domains-file", "D", "domains.txt", "file containing domains to check")
	rootCmd.Flags().IntP("workers", "w", 10, "amount of concurrent workers")
	rootCmd.Flags().StringP("output", "o", "", "file to write findings to")
	rootCmd.Flags().UintP("timeout", "t", 10, "timeout for HTTP requests")
	rootCmd.Flags().BoolP("edge-cases", "e", false, "include edge-case fingerprints (might cause false positives)")
	rootCmd.Flags().StringP("fingerprints", "f", "", "custom service fingerprints file")
	rootCmd.Flags().BoolP("verbose", "v", false, "increase application verbosity")
	rootCmd.Flags().BoolP("skip-summary", "s", false, "skip summary at the end of the scan")
}
