package cmd

import (
	"fmt"
	"github.com/analog-substance/nex/pkg/nmap"
	"github.com/spf13/cobra"
	"path/filepath"
	"slices"
)

// viewCmd represents the view command
var viewCmd = &cobra.Command{
	Use:   "view file/glob [file/glob...]",
	Short: "View Nmap XML scans in various forms",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		excludeThings, _ := cmd.Flags().GetStringSlice("exclude")
		includePublic, _ := cmd.Flags().GetBool("public")
		includePrivate, _ := cmd.Flags().GetBool("private")
		listIPs, _ := cmd.Flags().GetBool("ips")
		listHostnames, _ := cmd.Flags().GetBool("hostnames")
		jsonOutput, _ := cmd.Flags().GetBool("json")
		openOnly, _ := cmd.Flags().GetBool("open")
		upOnly, _ := cmd.Flags().GetBool("up")
		noTCPWrapped, _ := cmd.Flags().GetBool("no-tcpwrapped")

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

		viewOptions := nmap.ViewOptions(0)
		if includePublic {
			viewOptions = viewOptions | nmap.ViewPublic
		}

		if includePrivate {
			viewOptions = viewOptions | nmap.ViewPrivate
		}

		if upOnly {
			viewOptions = viewOptions | nmap.ViewAliveHosts
		}

		if openOnly {
			viewOptions = viewOptions | nmap.ViewOpenPorts
		}

		if noTCPWrapped {
			viewOptions = viewOptions | nmap.IgnoreTCPWrapped
		}

		if jsonOutput {
			err = nmapView.PrintJSON(viewOptions)
			check(err)
			return
		}

		if listHostnames || listIPs {
			if listHostnames {
				viewOptions = viewOptions | nmap.ListHostnames
			}
			if listIPs {
				viewOptions = viewOptions | nmap.ListIPs
			}

			nmapView.PrintList(viewOptions)
			return
		}

		sortBy, _ := cmd.Flags().GetString("sort-by")
		// no options specified
		nmapView.PrintTable(sortBy, viewOptions)

	},
}

func init() {
	RootCmd.AddCommand(viewCmd)
	viewCmd.Flags().String("sort-by", "Hostnames;asc", "Sort by the specified column. Format: column[;(asc|dsc)]")
	viewCmd.Flags().Bool("open", false, "Show only hosts with open ports")
	viewCmd.Flags().Bool("up", false, "Show only hosts that are up")
	viewCmd.Flags().Bool("hostnames", false, "Just list hostnames")
	viewCmd.Flags().Bool("private", false, "Only show hosts with private IPs")
	viewCmd.Flags().Bool("public", false, "Only show hosts with public IPs")
	viewCmd.Flags().Bool("ips", false, "Just list IP addresses")
	viewCmd.Flags().Bool("json", false, "Print JSON")
	viewCmd.Flags().Bool("no-tcpwrapped", false, "Do not show TCPWrapped ports")
	viewCmd.Flags().StringSlice("exclude", []string{}, "exclude")

}
