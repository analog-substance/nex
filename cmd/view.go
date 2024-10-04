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
		hostsOnly, _ := cmd.Flags().GetBool("hosts")
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

		columns := table.Row{"Name", "TCP", "UDP"}
		t.AppendHeader(columns)

		if jsonOutput {
			output, err := json.MarshalIndent(run.Hosts, "", "  ")
			if err != nil {
				check(err)
			}
			fmt.Println(string(output))
			return
		}

		if hostsOnly {
			hosts := map[string]bool{}
			for _, h := range run.Hosts {

				ipv4 := ""
				ipv6 := ""
				for _, addr := range h.Addresses {
					if addr.AddrType == "ipv4" && ipv4 == "" {
						ipv4 = addr.Addr
					} else if addr.AddrType == "ipv6" && ipv6 == "" {
						ipv6 = addr.Addr
					}
				}

				name := ipv6
				if len(h.Hostnames) > 0 {
					name = h.Hostnames[0].Name
				} else if ipv4 != "" {
					name = ipv4
				}

				hosts[name] = true
				continue
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

			ipv4 := ""
			ipv6 := ""
			for _, addr := range h.Addresses {
				if addr.AddrType == "ipv4" && ipv4 == "" {
					ipv4 = addr.Addr
				} else if addr.AddrType == "ipv6" && ipv6 == "" {
					ipv6 = addr.Addr
				}
			}

			name := ipv6
			if len(h.Hostnames) > 0 {
				name = h.Hostnames[0].Name
			} else if ipv4 != "" {
				name = ipv4
			}

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

			tcpPorts := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(tcp)), ","), "[]")
			udpPorts := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(udp)), ","), "[]")
			t.AppendRow(table.Row{name, tcpPorts, udpPorts})
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
			Name: "Name",
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
	viewCmd.Flags().Bool("hosts", false, "Just print hosts")
	viewCmd.Flags().Bool("json", false, "Print JSON")

}
