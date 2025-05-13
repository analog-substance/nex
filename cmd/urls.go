package cmd

import (
	"fmt"
	"github.com/analog-substance/nex/pkg/nmap"
	"github.com/spf13/cobra"
	"path/filepath"
	"slices"
	"strings"
)

// urlsCmd represents the view command
var urlsCmd = &cobra.Command{
	Use:   "urls file/glob [file/glob...]",
	Short: "Get URLs from nmap scan data",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		excludeThings, _ := cmd.Flags().GetStringSlice("exclude")
		protocolPrefix, _ := cmd.Flags().GetString("protocol")
		includePublic, _ := cmd.Flags().GetBool("public")
		includePrivate, _ := cmd.Flags().GetBool("private")
		excludePorts, _ := cmd.Flags().GetIntSlice("exclude-ports")
		includePorts, _ := cmd.Flags().GetIntSlice("include-ports")
		//useHostnames, _ := cmd.Flags().GetBool("hostnames")
		//useIPs, _ := cmd.Flags().GetBool("ips")

		var files []string
		for _, pattern := range args {
			matches, err := filepath.Glob(pattern)
			check(err)

			files = append(files, matches...)
		}

		if len(files) == 0 {
			check(fmt.Errorf("no files found"))
		}

		var opts []nmap.Option
		run, err := nmap.XMLMerge(files, opts...)
		check(err)

		nmapView := nmap.NewNmapView(run)

		if len(excludeThings) > 0 {
			nmapView.SetFilter(func(hostnames []string, ips []string) bool {
				for _, exclude := range excludeThings {
					if slices.Contains(hostnames, exclude) {
						return false
					}

					if slices.Contains(ips, exclude) {
						return false
					}
				}
				return true
			})
		}

		nmapView.SetExcludePorts(excludePorts)
		nmapView.SetIncludePorts(includePorts)

		viewOptions := nmap.ViewOptions(0)
		if includePublic {
			viewOptions = viewOptions | nmap.ViewPublic
		}

		if includePrivate {
			viewOptions = viewOptions | nmap.ViewPrivate
		}

		urls := nmapView.GetURLs(protocolPrefix, viewOptions)

		fmt.Println(strings.Join(urls, "\n"))

	},
}

func init() {
	RootCmd.AddCommand(urlsCmd)
	//urlsCmd.Flags().Bool("hostnames", false, "Just list hostnames")
	urlsCmd.Flags().Bool("private", false, "Only show hosts with private IPs")
	urlsCmd.Flags().Bool("public", false, "Only show hosts with public IPs")
	//urlsCmd.Flags().Bool("ips", false, "Just list IP addresses")
	urlsCmd.Flags().StringP("protocol", "p", "", "protocol prefix")
	urlsCmd.Flags().StringSlice("exclude", []string{}, "exclude")
	urlsCmd.Flags().IntSlice("exclude-ports", []int{}, "Exclude hosts that have these ports open")
	urlsCmd.Flags().IntSlice("include-ports", []int{}, "Include these ports from the output")

}
