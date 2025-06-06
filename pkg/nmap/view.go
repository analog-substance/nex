package nmap

import (
	"encoding/json"
	"fmt"
	"github.com/Ullaakut/nmap/v2"
	"github.com/analog-substance/nex/pkg/dns_guard_rail"
	"github.com/analog-substance/util/set"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"log"
	"net"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
)

type ViewOptions int32

const (
	ViewPrivate = 1 << iota
	ViewPublic
	ViewAliveHosts
	ViewOpenPorts
	ListIPs
	ListHostnames
	IgnoreTCPWrapped
)

type View struct {
	run          *nmap.Run
	filter       func(hostnames []string, ips []string) bool
	hosts        []*nmap.Host
	excludePorts []int
	includePorts []int
}

func NewNmapView(run *nmap.Run) *View {
	return &View{
		run:          run,
		filter:       defaultFilter,
		excludePorts: []int{},
		includePorts: []int{},
	}
}

func defaultFilter(hostnames []string, ips []string) bool {
	return true
}

func (v *View) SetFilter(filter func(hostnames []string, ips []string) bool) {
	v.filter = filter
}

func (v *View) SetExcludePorts(ports []int) {
	v.excludePorts = ports
}

func (v *View) SetIncludePorts(ports []int) {
	v.includePorts = ports
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

func (v *View) GetURLs(prefix string, options ViewOptions) []string {

	urlSet := set.NewStringSet()
	httpProtocolRe := regexp.MustCompile(`^https?`)

	for _, host := range v.GetHostsWithOptions(options) {
		for _, port := range host.Ports {

			// check to see if this port should be ignored
			if slices.Contains(v.excludePorts, int(port.ID)) {
				continue
			}

			// check to see if this port should be included
			if len(v.includePorts) > 0 && !slices.Contains(v.includePorts, int(port.ID)) {
				continue
			}

			if port.Service.Name == "tcpwrapped" {
				continue
			}

			if !portIsOpen(&port) {
				continue
			}

			proto := port.Service.Name

			if port.ID == 443 {
				proto = "https"
			} else if port.ID == 80 {
				proto = "http"
			} else if httpProtocolRe.MatchString(proto) {
				proto = httpProtocolRe.FindString(proto)
			}

			urlPort := fmt.Sprintf(":%d", port.ID)
			if proto == "http" && port.ID == 80 || proto == "https" && port.ID == 443 {
				urlPort = ""
			}

			if !strings.HasPrefix(proto, prefix) {
				continue
			}

			isCDN := false
			for _, hostname := range host.Hostnames {
				if dns_guard_rail.IsCDN(hostname.Name) {
					isCDN = true
					break
				}
			}

			if proto == "" {
				bytes, err := json.Marshal(port)
				if err == nil {
					log.Println("empty protocol", string(bytes))
				}
			} else {
				proto = fmt.Sprintf("%s://", proto)
			}

			if !isCDN {
				// not a CDN? add the IP addresses
				for _, addr := range host.Addresses {
					urlSet.Add(fmt.Sprintf("%s%s%s", proto, addr.Addr, urlPort))
				}
			}

			if strings.HasPrefix(proto, "http") {
				// HTTP eh? add other hostnames so we can test virtual hosting
				for _, hostname := range host.Hostnames {
					if !dns_guard_rail.ShouldInvestigateMore(hostname.Name) {
						// Don't care....
						continue
					}

					urlSet.Add(fmt.Sprintf("%s%s%s", proto, hostname.Name, urlPort))
				}
			}
		}
	}

	return urlSet.StringSlice()
}

func (v *View) GetHostsWithOptions(options ViewOptions) []*nmap.Host {
	hosts := v.GetHosts()
	returnHosts := []*nmap.Host{}
	for _, h := range hosts {

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
			} else {
				hasPublicIPs = true
			}
		}

		// we want private IPs, but this host doesnt have any, skip it
		if options&ViewPrivate != 0 && !hasPrivateIPs {
			continue
		}

		// we want public IPs, but this host doesnt have any, skip it
		if options&ViewPublic != 0 && !hasPublicIPs {
			continue
		}

		hostHasOpenPorts := hasOpenPorts(h)

		// we want up hosts and this host is not up
		if options&ViewAliveHosts != 0 && h.Status.State != "up" && !hostHasOpenPorts {
			continue
		}

		// we want open ports
		if options&ViewOpenPorts != 0 && !hostHasOpenPorts {
			continue
		}

		// Skip hosts that only have excluded ports open
		if len(v.excludePorts) > 0 && v.hostOnlyHasExcludedPorts(h) {
			continue
		}

		// Skip hosts that do not have port that we want
		if len(v.includePorts) > 0 && !portsContains(h.Ports, v.includePorts) {
			continue
		}

		returnHosts = append(returnHosts, h)
	}

	return returnHosts
}

func (v *View) hostOnlyHasExcludedPorts(host *nmap.Host) bool {
	if len(host.Ports) == 0 {
		return false
	}

	for _, port := range host.Ports {
		if port.State.State == "open" {
			portID := int(port.ID)
			if !slices.Contains(v.excludePorts, portID) {
				return false
			}
		}
	}

	hasOpenExcludedPort := false
	for _, port := range host.Ports {
		if port.State.State == "open" {
			portID := int(port.ID)
			if slices.Contains(v.excludePorts, portID) {
				hasOpenExcludedPort = true
				break
			}
		}
	}

	return hasOpenExcludedPort
}

func portsContains(hostPorts []nmap.Port, portsToCheck []int) bool {
	for _, hp := range hostPorts {
		for _, port := range portsToCheck {
			if int(hp.ID) == port {
				return true
			}
		}
	}
	return false
}

func (v *View) PrintJSON(options ViewOptions) error {
	hosts := v.GetHostsWithOptions(options)
	output, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}

func (v *View) PrintList(options ViewOptions) {
	hosts := map[string]bool{}
	for _, h := range v.GetHostsWithOptions(options) {

		for _, addr := range h.Addresses {
			ip := net.ParseIP(addr.Addr)
			if ip == nil {
				continue
			}

			if options&ListIPs != 0 {
				hosts[addr.Addr] = true
			}
		}

		for _, hostname := range h.Hostnames {
			if options&ListHostnames != 0 {
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

func (v *View) PrintTable(sortByArg string, options ViewOptions) {

	re := lipgloss.NewRenderer(os.Stdout)
	baseStyle := re.NewStyle().Padding(0, 1)
	headerStyle := baseStyle.Foreground(lipgloss.Color("252")).Bold(true)

	CapitalizeHeaders := func(data []string) []string {
		for i := range data {
			data[i] = strings.ToUpper(data[i])
		}
		return data
	}

	ignoreTCPWrapped := options&IgnoreTCPWrapped != 0
	portColumnWidth := 50
	data := [][]string{}
	var headers = []string{"IP", "Hostnames", "TCP", "UDP"}
	for _, h := range v.GetHostsWithOptions(options) {
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

		var hostnames []string
		for _, hostname := range h.Hostnames {
			hostnames = append(hostnames, hostname.Name)
		}
		sort.Strings(hostnames)

		var tcp []int
		var udp []int
		for _, p := range h.Ports {
			if portIsOpen(&p) {
				port := int(p.ID)

				if slices.Contains(v.excludePorts, port) {
					continue
				}

				if strings.EqualFold(p.Protocol, "tcp") {
					if !ignoreTCPWrapped || p.Service.Name != "tcpwrapped" {
						tcp = append(tcp, port)
					}
				} else {
					udp = append(udp, port)
				}
			}
		}

		if ignoreTCPWrapped && len(tcp) == 0 && len(udp) == 0 {
			// this will still need to be done for the other views :(
			// need to think of a better way to filter this data in the nmap run
			// or view filter
			continue
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
		currentLine := len(portLines) - 1
		if currentLine == -1 {
			portLines = append(portLines, fmt.Sprint(port))
			continue
		}
		portStrLen := len(portLines[currentLine])

		var nextPort string
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
