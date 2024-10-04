package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/analog-substance/nex/pkg/nmap"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

// viewCmd represents the view command
var viewCmd = &cobra.Command{
	Use:   "view file/glob [file/glob...]",
	Short: "View Nmap XML scans in various forms",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ipListOnly, _ := cmd.Flags().GetBool("ip-list")
		hostListOnly, _ := cmd.Flags().GetBool("host-list")
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
			check(fmt.Errorf("No files found"))
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

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)

		columns := table.Row{"IP", "Hostnames", "TCP", "UDP"}
		t.AppendHeader(columns)

		if jsonOutput {
			output, err := json.MarshalIndent(run.Hosts, "", "  ")
			if err != nil {
				check(err)
			}
			fmt.Println(string(output))
			return
		}

		if ipListOnly || hostListOnly {
			hosts := map[string]bool{}
			for _, h := range run.Hosts {
				if ipListOnly {
					for _, addr := range h.Addresses {
						hosts[addr.Addr] = true
					}
				} else if hostListOnly {
					for _, hostname := range h.Hostnames {
						hosts[hostname.Name] = true
					}
				}
			}
			var hostSlice []string
			for host := range hosts {
				hostSlice = append(hostSlice, host)
			}
			sort.Strings(hostSlice)
			fmt.Println(strings.Join(hostSlice, "\n"))
			return
		}
		for _, h := range run.Hosts {

			var ipAddrs []string
			for _, addr := range h.Addresses {
				ipAddrs = append(ipAddrs, addr.Addr)
			}
			sort.Strings(ipAddrs)

			var hostnames []string
			for _, hostname := range h.Hostnames {
				hostnames = append(hostnames, hostname.Name)
			}
			sort.Strings(hostnames)

			var tcp []int
			var udp []int
			for _, p := range h.Ports {
				port := int(p.ID)
				if strings.EqualFold(p.Protocol, "tcp") {
					tcp = append(tcp, port)
				} else {
					udp = append(udp, port)
				}
			}

			sort.Ints(tcp)
			sort.Ints(udp)

			ipAddrsStr := strings.Join(ipAddrs, ",")
			hostnamesStr := strings.Join(hostnames, "\n")
			tcpPorts := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(tcp)), ","), "[]")
			udpPorts := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(udp)), ","), "[]")
			t.AppendRow(table.Row{ipAddrsStr, hostnamesStr, tcpPorts, udpPorts})
		}

		if t.Length() == 0 {
			return
		}

		t.SetColumnConfigs([]table.ColumnConfig{
			{
				Name:     "TCP",
				WidthMax: 50,
			},
			{
				Name:     "UDP",
				WidthMax: 50,
			},
		})

		sortByArg, _ := cmd.Flags().GetString("sort-by")
		parts := strings.Split(sortByArg, ";")

		sortBy := table.SortBy{
			Name: "IP",
			Mode: table.Asc,
		}

		sortColumn := parts[0]
		for _, col := range columns {
			if strings.EqualFold(col.(string), sortColumn) {
				sortBy.Name = col.(string)
				break
			}
		}

		if len(parts) > 1 && strings.EqualFold(parts[1], "dsc") {
			sortBy.Mode = table.Dsc
		}

		t.SortBy([]table.SortBy{
			sortBy,
		})
		t.Render()
	},
}

func init() {
	RootCmd.AddCommand(viewCmd)
	viewCmd.Flags().String("sort-by", "Name;asc", "Sort by the specified column. Format: column[;(asc|dsc)]")
	viewCmd.Flags().Bool("open", false, "Show only hosts with open ports")
	viewCmd.Flags().Bool("up", false, "Show only hosts that are up")
	viewCmd.Flags().Bool("host-list", false, "Just print hostnames")
	viewCmd.Flags().Bool("ip-list", false, "Just print IP addresses")
	viewCmd.Flags().Bool("json", false, "Print JSON")
}
