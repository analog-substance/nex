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
	ListViewAliveHosts
	ListViewOpenPorts
)

const (
	TableViewPrivate = 1 << iota
	TableViewPublic
	TableViewAliveHosts
	TableViewOpenPorts
)

type View struct {
	run    *nmap.Run
	filter func(hostnames []string, ips []string) bool
	hosts  []*nmap.Host
}

func NewNmapView(run *nmap.Run) *View {
	return &View{
		run:    run,
		filter: defaultFilter,
	}
}

func defaultFilter(hostnames []string, ips []string) bool {
	return true
}

func (v *View) SetFilter(filter func(hostnames []string, ips []string) bool) {
	v.filter = filter
}

func (v *View) GetHosts() []*nmap.Host {
	if v.hosts == nil {
		v.hosts = []*nmap.Host{}
		for _, host := range v.run.Hosts {
			if v.filter != nil {

				hostnames := []string{}
				ips := []string{}

				for _, ip := range host.Addresses {
					ips = append(ips, ip.String())
				}
				for _, hostname := range host.Hostnames {
					hostnames = append(hostnames, hostname.Name)
				}

				if v.filter(hostnames, ips) {
					v.hosts = append(v.hosts, &host)
				}
			}
		}
	}

	return v.hosts
}

func (v *View) PrintJSON() error {
	output, err := json.MarshalIndent(v.GetHosts(), "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

func (v *View) PrintList(options ListViewOptions) {
	hosts := map[string]bool{}
	for _, h := range v.GetHosts() {
		hasPrivateIPs := false
		hasPublicIPs := false

		hostHasOpenPorts := hasOpenPorts(h)

		// we want up hosts and this host is not up
		if options&ListViewAliveHosts != 0 && h.Status.State != "up" && !hostHasOpenPorts {
			continue
		}

		// we want open ports
		if options&ListViewOpenPorts != 0 && !hostHasOpenPorts {
			continue
		}

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

	portColumnWidth := 50
	data := [][]string{}
	var headers = []string{"IP", "Hostnames", "TCP", "UDP"}
	for _, h := range v.GetHosts() {
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

		hostHasOpenPorts := hasOpenPorts(h)

		// we want up hosts and this host is not up
		if options&TableViewAliveHosts != 0 && h.Status.State != "up" && !hostHasOpenPorts {
			continue
		}

		// we want open ports
		if options&TableViewOpenPorts != 0 && !hostHasOpenPorts {
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

		tcpPorts := wrapPorts(tcp, portColumnWidth)
		udpPorts := wrapPorts(udp, portColumnWidth)

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

func wrapPorts(ports []int, portColumnWidth int) string {

	portLines := []string{}
	for _, port := range ports {
		var nextPort string
		currentLine := len(portLines) - 1
		if currentLine == -1 {
			portLines = append(portLines, fmt.Sprint(port))
			continue
		}
		portStrLen := len(portLines[currentLine])

		if portStrLen > 0 {
			nextPort = fmt.Sprintf(",%d", port)
		} else {
			nextPort = fmt.Sprint(port)
		}

		if portStrLen+len(nextPort) < portColumnWidth {
			portLines[currentLine] += nextPort
		} else {
			portLines = append(portLines, nextPort)
		}
	}

	return strings.Join(portLines, "\n")
}
