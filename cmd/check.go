package cmd

import (
	"github.com/mdeous/dnscheck/checker"
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
		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			log.Fatal(err.Error())
		}
		fpFile, err := cmd.Flags().GetString("fingerprints")
		if err != nil {
			log.Fatal(err.Error())
		}
		domainFile, err := cmd.Flags().GetString("domains")
		if err != nil {
			log.Fatal(err.Error())
		}
		nameserver, err := cmd.Flags().GetString("nameserver")
		if err != nil {
			log.Fatal(err.Error())
		}
		useSSL, err := cmd.Flags().GetBool("ssl")
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

		// instanciate domain checker
		chk := checker.NewChecker(&checker.Config{
			Nameserver:   nameserver,
			Verbose:      verbose,
			UseSSL:       useSSL,
			Workers:      workers,
			CustomFpFile: fpFile,
			HttpTimeout:  timeout,
		})

		// load target domains
		go utils.ReadLines(domainFile, chk.Domains)

		// scan domains and read results
		var findings []*checker.Finding
		chk.Scan()
		for f := range chk.Results() {
			log.Finding("[service: %s] %s %s: %s (method: %s)", f.Service, f.Domain, f.Type, f.Target, f.Method)
			if output != "" {
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
	checkCmd.Flags().StringP("domains", "d", "domains.txt", "file containing domains to check")
	err := checkCmd.MarkFlagRequired("domains")
	if err != nil {
		log.Fatal(err.Error())
	}
	checkCmd.Flags().StringP("nameserver", "n", "8.8.8.8:53", "server and port to use for name resolution")
	checkCmd.Flags().BoolP("ssl", "S", false, "use HTTPS when connecting to targets")
	checkCmd.Flags().IntP("workers", "w", 10, "amount of concurrent workers")
	checkCmd.Flags().StringP("output", "o", "", "file to write findings to")
	checkCmd.Flags().UintP("timeout", "t", 10, "timeout for HTTP requests")
}
