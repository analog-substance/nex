package cmd

import (
	"fmt"
	"os"
	"path/filepath"
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
			var tcp []string
			var udp []string
			for _, p := range h.Ports {
				// port := fmt.Sprintf("%d/%s", p.ID, p.Service)
				port := fmt.Sprintf("%d", p.ID)
				if p.Protocol == "tcp" {
					tcp = append(tcp, port)
				} else {
					udp = append(udp, port)
				}
			}

			if openOnly && len(tcp) == 0 && len(udp) == 0 {
				continue
			}

			name := h.Addresses[0].String()
			if len(h.Hostnames) > 0 {
				name = h.Hostnames[0].String()
			}

			t.AppendRow(table.Row{name, strings.Join(tcp, ","), strings.Join(udp, ",")})
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
