package cmd

import (
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "dnscheck",
	Short: "Domain hijacking assessment tool",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.PersistentFlags().StringP("fingerprints", "f", "", "custom fingerprints file")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "increase application verbosity")
}
