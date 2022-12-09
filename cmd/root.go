package cmd

import (
	"fmt"
	"os"
	"path/filepath"

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

		ignoreXML, _ := cmd.Flags().GetBool("ignore-xml")
		if !ignoreXML {
			err := nmap.XMLToHosts(ensureExt(path, ".xml"), name)
			if err != nil && !os.IsNotExist(err) {
				fmt.Println(err)
			}
		}

		ignoreNmap, _ := cmd.Flags().GetBool("ignore-nmap")
		if !ignoreNmap {
			err := nmap.NmapToHosts(ensureExt(path, ".nmap"), name)
			if err != nil && !os.IsNotExist(err) {
				fmt.Println(err)
			}
		}

		ignoreGnmap, _ := cmd.Flags().GetBool("ignore-gnmap")
		if !ignoreGnmap {
			err := nmap.GnmapToHosts(ensureExt(path, ".gnmap"), name)
			if err != nil && !os.IsNotExist(err) {
				fmt.Println(err)
			}
		}
	},
}

func ensureExt(path string, ext string) string {
	pathExt := filepath.Ext(path)
	if pathExt != ext {
		path = fmt.Sprintf("%s%s", path, ext)
	}
	return path
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
	rootCmd.Flags().Bool("ignore-nmap", false, "Ignore .nmap files.")
	rootCmd.Flags().Bool("ignore-gnmap", false, "Ignore .gnmap files.")
	rootCmd.Flags().Bool("ignore-xml", false, "Ignore .xml files.")
}
