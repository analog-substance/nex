package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/analog-substance/nex/pkg/nmap"
	"github.com/spf13/cobra"
)

// splitCmd represents the split command
var splitCmd = &cobra.Command{
	Use:   "split",
	Short: "Split nmap scans into separate files for each host scanned.",
	Run: func(cmd *cobra.Command, args []string) {
		path, _ := cmd.Flags().GetString("path")
		name, _ := cmd.Flags().GetString("name")

		ignoreXML, _ := cmd.Flags().GetBool("ignore-xml")
		if !ignoreXML {
			err := nmap.XMLSplit(ensureExt(path, ".xml"), name)
			if err != nil && !os.IsNotExist(err) {
				fmt.Println(err)
			}
		}

		ignoreNmap, _ := cmd.Flags().GetBool("ignore-nmap")
		if !ignoreNmap {
			err := nmap.NmapSplit(ensureExt(path, ".nmap"), name)
			if err != nil && !os.IsNotExist(err) {
				fmt.Println(err)
			}
		}

		ignoreGnmap, _ := cmd.Flags().GetBool("ignore-gnmap")
		if !ignoreGnmap {
			err := nmap.GnmapSplit(ensureExt(path, ".gnmap"), name)
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

func init() {
	RootCmd.AddCommand(splitCmd)

	splitCmd.Flags().StringP("path", "p", "", "Path of nmap files without the extension")
	splitCmd.MarkFlagRequired("path")

	splitCmd.Flags().StringP("name", "n", "nmap-tcp", "Name of the file to be used for each host, without the extension.")
	splitCmd.Flags().Bool("ignore-nmap", false, "Ignore .nmap files.")
	splitCmd.Flags().Bool("ignore-gnmap", false, "Ignore .gnmap files.")
	splitCmd.Flags().Bool("ignore-xml", false, "Ignore .xml files.")
}
