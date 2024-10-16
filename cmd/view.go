package cmd

import (
	"fmt"
	"github.com/analog-substance/nex/pkg/nmap"
	"github.com/spf13/cobra"
	"path/filepath"
)

// viewCmd represents the view command
var viewCmd = &cobra.Command{
	Use:   "view file/glob [file/glob...]",
	Short: "View Nmap XML scans in various forms",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		includePublic, _ := cmd.Flags().GetBool("public")
		includePrivate, _ := cmd.Flags().GetBool("private")
		listIPs, _ := cmd.Flags().GetBool("ips")
		listHostnames, _ := cmd.Flags().GetBool("hostnames")
		jsonOutput, _ := cmd.Flags().GetBool("json")
		openOnly, _ := cmd.Flags().GetBool("open")
		upOnly, _ := cmd.Flags().GetBool("up")

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

		if jsonOutput {
			err = nmapView.PrintJSON()
			check(err)
			return
		}

		viewOptions := nmap.ListViewOptions(0)
		if listHostnames {
			if includePublic {
				viewOptions = viewOptions | nmap.ListViewPublicHostnames
			}
			if includePrivate {
				viewOptions = viewOptions | nmap.ListViewPrivateHostnames
			}
		}

		if listIPs {
			if includePublic {
				viewOptions = viewOptions | nmap.ListViewPublicIPs
			}
			if includePrivate {
				viewOptions = viewOptions | nmap.ListViewPrivateIPs
			}
		}

		if viewOptions > 0 {
			if upOnly {
				viewOptions = viewOptions | nmap.ListViewAliveHosts
			}
			if openOnly {
				viewOptions = viewOptions | nmap.ListViewOpenPorts
			}

			nmapView.PrintList(viewOptions)
			return
		}

		tableViewOptions := nmap.TableViewOptions(0)
		if includePublic {
			tableViewOptions = tableViewOptions | nmap.TableViewPublic
		}
		if includePrivate {
			tableViewOptions = tableViewOptions | nmap.TableViewPrivate
		}

		if upOnly {
			tableViewOptions = tableViewOptions | nmap.TableViewAliveHosts
		}
		if openOnly {
			tableViewOptions = tableViewOptions | nmap.TableViewOpenPorts
		}

		sortBy, _ := cmd.Flags().GetString("sort-by")
		// no options specified
		nmapView.PrintTable(sortBy, tableViewOptions)

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
}
