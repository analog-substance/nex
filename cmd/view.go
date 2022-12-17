package cmd

import (
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
		openOnly, _ := cmd.Flags().GetBool("open")

		var files []string
		for _, pattern := range args {
			matches, err := filepath.Glob(pattern)
			check(err)

			files = append(files, matches...)
		}

		run, err := nmap.XMLMerge(files)
		check(err)

		t := table.NewWriter()
		t.SetOutputMirror(os.Stdout)

		columns := table.Row{"Name", "TCP", "UDP"}
		t.AppendHeader(columns)

		for _, h := range run.Hosts {
			var tcp []int
			var udp []int
			for _, p := range h.Ports {
				if openOnly && p.State.State == "closed" {
					continue
				}

				port := int(p.ID)
				if strings.EqualFold(p.Protocol, "tcp") {
					tcp = append(tcp, port)
				} else {
					udp = append(udp, port)
				}
			}

			sort.Ints(tcp)
			sort.Ints(udp)

			if openOnly && len(tcp) == 0 && len(udp) == 0 {
				continue
			}

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

			tcpPorts := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(tcp)), ","), "[]")
			udpPorts := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(udp)), ","), "[]")
			t.AppendRow(table.Row{name, tcpPorts, udpPorts})
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
	rootCmd.AddCommand(viewCmd)

	viewCmd.Flags().String("sort-by", "Name;asc", "Sort by the specified column. Format: column[;(asc|dsc)]")
	viewCmd.Flags().Bool("open", false, "Show only hosts with open ports")
}
