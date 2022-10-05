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
	Run: func(cmd *cobra.Command, args []string) {
		path, _ := cmd.Flags().GetString("path")
		name, _ := cmd.Flags().GetString("name")

		err := nmap.XMLToHosts(fmt.Sprintf("%s.xml", path), name)
		if err != nil && !os.IsNotExist(err) {
			fmt.Println(err)
		}

		err = nmap.NmapToHosts(fmt.Sprintf("%s.nmap", path), name)
		if err != nil && !os.IsNotExist(err) {
			fmt.Println(err)
		}

		err = nmap.GnmapToHosts(fmt.Sprintf("%s.gnmap", path), name)
		if err != nil && !os.IsNotExist(err) {
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

	rootCmd.Flags().StringP("name", "n", "nmap-tcp", "Name of the file to be used for each host, without the extension.")
}
