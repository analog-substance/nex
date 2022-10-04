package cmd

import (
	"fmt"
	"os"

	"github.com/analog-substance/nmap2host/pkg/nmap"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "nmap2host",
	Short: "Split nmap scans into separate files for each host scanned.",
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		path, _ := cmd.Flags().GetString("path")
		err := nmap.XMLToHosts(fmt.Sprintf("%s.xml", path))
		if err != nil {
			fmt.Println(err)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringP("path", "p", "", "Path of nmap files without the extension")
	rootCmd.MarkFlagRequired("path")
}
