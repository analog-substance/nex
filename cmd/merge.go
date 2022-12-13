package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/analog-substance/nex/pkg/nmap"
	"github.com/spf13/cobra"
)

// mergeCmd represents the merge command
var mergeCmd = &cobra.Command{
	Use:   "merge file/glob [file/glob...]",
	Short: "Merge Nmap XML files into one",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		var files []string
		for _, pattern := range args {
			matches, err := filepath.Glob(pattern)
			check(err)

			files = append(files, matches...)
		}

		run, err := nmap.XMLMerge(files)
		check(err)

		err = run.ToFile(output)
		check(err)
	},
}

func check(err error) {
	if err != nil {
		fmt.Printf("[!] %v", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(mergeCmd)

	mergeCmd.Flags().StringP("output", "o", "nmap-merge.xml", "Output of resulting merged file.")
}
