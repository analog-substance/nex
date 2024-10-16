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
		listPublicIPs, _ := cmd.Flags().GetBool("pub-ips")
		listPrivateIPs, _ := cmd.Flags().GetBool("priv-ips")
		listIPs, _ := cmd.Flags().GetBool("ips")
		listPublicHostnames, _ := cmd.Flags().GetBool("pub-hostnames")
		listPrivateHostnames, _ := cmd.Flags().GetBool("priv-hostnames")
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
		if upOnly {
			opts = append(opts, nmap.WithUpOnly())
		}
		if openOnly {
			opts = append(opts, nmap.WithOpenOnly())
		}

		run, err := nmap.XMLMerge(files, opts...)
		check(err)

		nmapView := nmap.NewNmapView(run)

		if jsonOutput {
			err = nmapView.PrintJSON()
			check(err)
			return
		}

		viewOptions := nmap.ViewOptions(0)
		if listHostnames {
			listPublicHostnames = true
			listPrivateHostnames = true
		}

		if listIPs {
			listPublicIPs = true
			listPrivateIPs = true
		}

		if listPublicHostnames {
			viewOptions = viewOptions | nmap.ViewListPublicHostnames
		}
		if listPrivateHostnames {
			viewOptions = viewOptions | nmap.ViewListPrivateHostnames
		}
		if listPublicIPs {
			viewOptions = viewOptions | nmap.ViewListPublicIPs
		}
		if listPrivateIPs {
			viewOptions = viewOptions | nmap.ViewListPrivateIPs
		}

		if viewOptions > 0 {
			nmapView.PrintList(viewOptions)
			return
		}

		sortBy, _ := cmd.Flags().GetString("sort-by")
		// no options specified
		nmapView.PrintTable(sortBy)

	},
}

func init() {
	RootCmd.AddCommand(viewCmd)
	viewCmd.Flags().String("sort-by", "Hostnames;asc", "Sort by the specified column. Format: column[;(asc|dsc)]")
	viewCmd.Flags().Bool("open", false, "Show only hosts with open ports")
	viewCmd.Flags().Bool("up", false, "Show only hosts that are up")
	viewCmd.Flags().Bool("pub-hostnames", false, "Just print public hostnames")
	viewCmd.Flags().Bool("priv-hostnames", false, "Just print private hostnames")
	viewCmd.Flags().Bool("hostnames", false, "Just print hostnames")
	viewCmd.Flags().Bool("pub-ips", false, "Just print public IP addresses")
	viewCmd.Flags().Bool("priv-ips", false, "Just print private IP addresses")
	viewCmd.Flags().Bool("ips", false, "Just print IP addresses")
	viewCmd.Flags().Bool("json", false, "Print JSON")
}
