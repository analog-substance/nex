package nmap

import (
	"encoding/json"
	"fmt"
	"github.com/Ullaakut/nmap/v2"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
)

type ListViewOptions int32
type TableViewOptions int32

const (
	ListViewPrivateIPs = 1 << iota
	ListViewPublicIPs
	ListViewPrivateHostnames
	ListViewPublicHostnames
)

const (
	TableViewPrivate = 1 << iota
	TableViewPublic  = 1 << iota
)

type View struct {
	run *nmap.Run
}

func NewNmapView(run *nmap.Run) *View {
	return &View{
		run: run,
	}
}

func (v *View) PrintJSON() error {
	output, err := json.MarshalIndent(v.run.Hosts, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

func (v *View) PrintList(options ListViewOptions) {
	hosts := map[string]bool{}
	for _, h := range v.run.Hosts {
		hasPrivateIPs := false
		hasPublicIPs := false
		for _, addr := range h.Addresses {
			ip := net.ParseIP(addr.Addr)
			if ip == nil {
				continue
			}
			isPrivate := ip.IsPrivate()

			if isPrivate {
				hasPrivateIPs = true
				if options&ListViewPrivateIPs != 0 {
					hosts[addr.Addr] = true
				}
			} else {
				hasPublicIPs = true
				if options&ListViewPublicIPs != 0 {
					hosts[addr.Addr] = true
				}
			}
		}

		for _, hostname := range h.Hostnames {
			if (hasPrivateIPs && options&ListViewPrivateHostnames != 0) || (hasPublicIPs && options&ListViewPublicHostnames != 0) {
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
}

func (v *View) PrintTable(sortByArg string, options TableViewOptions) {

	re := lipgloss.NewRenderer(os.Stdout)
	baseStyle := re.NewStyle().Padding(0, 1)
	headerStyle := baseStyle.Foreground(lipgloss.Color("252")).Bold(true)

	CapitalizeHeaders := func(data []string) []string {
		for i := range data {
			data[i] = strings.ToUpper(data[i])
		}
		return data
	}

	data := [][]string{}
	var headers = []string{"IP", "Hostnames", "TCP", "UDP"}
	for _, h := range v.run.Hosts {
		hasPrivate := false
		hasPublic := false

		var ipAddrs []string
		for _, addr := range h.Addresses {
			ip := net.ParseIP(addr.Addr)
			if ip == nil {
				continue
			}
			if !hasPrivate {
				hasPrivate = ip.IsPrivate()
			}
			if !hasPublic {
				hasPublic = !ip.IsPrivate()
			}
			ipAddrs = append(ipAddrs, addr.Addr)
		}
		sort.Strings(ipAddrs)

		// we want private IPs, but this host doesnt have any, skip it
		if options&TableViewPrivate != 0 && !hasPrivate {
			continue
		}

		// we want public IPs, but this host doesnt have any, skip it
		if options&TableViewPublic != 0 && !hasPublic {
			continue
		}

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

		ipAddrsStr := strings.Join(ipAddrs, "\n")
		hostnamesStr := strings.Join(hostnames, "\n")
		tcpPorts := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(tcp)), ","), "[]")
		udpPorts := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(udp)), ","), "[]")

		data = append(data, []string{
			ipAddrsStr, hostnamesStr, tcpPorts, udpPorts,
		})
	}

	parts := strings.Split(sortByArg, ";")
	sortColumnName := parts[0]
	sortMode := "asc"
	if len(parts) > 1 {
		sortMode = parts[1]
	}
	sortColumnIndex := 0
	for i, col := range headers {
		if strings.EqualFold(col, sortColumnName) {
			sortColumnIndex = i
			break
		}
	}

	sort.SliceStable(data, func(i, j int) bool {
		sorted := []string{data[i][sortColumnIndex], data[j][sortColumnIndex]}
		slices.Sort(sorted)
		if sortMode == "asc" {
			return sorted[0] == data[i][sortColumnIndex]
		} else {
			return sorted[0] == data[j][sortColumnIndex]
		}
	})

	ct := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(re.NewStyle().Foreground(lipgloss.Color("238"))).
		Headers(CapitalizeHeaders(headers)...).
		Rows(data...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == 0 {
				return headerStyle
			}

			even := row%2 == 0

			if even {
				return baseStyle.Foreground(lipgloss.Color("245"))
			}
			return baseStyle.Foreground(lipgloss.Color("252"))
		})
	fmt.Println(ct)
}
