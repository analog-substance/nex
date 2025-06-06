package nmap

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Ullaakut/nmap/v2"
	"github.com/analog-substance/util/set"
)

const xmlHeader string = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="/static/nmap.xsl" type="text/xsl"?>
`

func XMLSplit(path string, name string) error {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	run, err := nmap.Parse(bytes)
	if err != nil {
		return err
	}

	for _, h := range run.Hosts {
		fmt.Printf("[+] Processing host: %s\n", h.Addresses[0])
		hostRun := newXMLRun(run)
		hostRun.Hosts = []nmap.Host{h}

		bytes, err := xml.MarshalIndent(hostRun, "", "  ")
		if err != nil {
			return err
		}
		bytes = append([]byte(xmlHeader), bytes...)

		var hostnames []string
		for _, hostname := range h.Hostnames {
			hostnames = append(hostnames, hostname.Name)
		}

		var ips []string
		for _, ip := range h.Addresses {
			ips = append(ips, ip.Addr)
		}

		currentHost, err := getHost(hostnames, ips)
		if err != nil {
			return err
		}

		err = writeToFile(currentHost, fmt.Sprintf("%s.xml", name), bytes)
		if err != nil {
			return err
		}
	}

	return nil
}

func newXMLRun(run *nmap.Run) *nmap.Run {
	return &nmap.Run{
		XMLName:          run.XMLName,
		Args:             run.Args,
		ProfileName:      run.ProfileName,
		Scanner:          run.Scanner,
		StartStr:         run.StartStr,
		Version:          run.Version,
		XMLOutputVersion: run.XMLOutputVersion,
		Debugging:        run.Debugging,
		Stats:            run.Stats,
		Start:            run.Start,
		Verbose:          run.Verbose,
		NmapErrors:       run.NmapErrors,
		PostScripts:      run.PostScripts,
		PreScripts:       run.PreScripts,
		Targets:          run.Targets,
		TaskBegin:        run.TaskBegin,
		TaskProgress:     run.TaskProgress,
		TaskEnd:          run.TaskEnd,
		ScanInfo:         run.ScanInfo,
	}
}

func XMLMerge(paths []string, opts ...Option) (*nmap.Run, error) {
	options := &Options{}
	for _, o := range opts {
		o(options)
	}

	var merged *nmap.Run
	hostsMap := make(map[string]nmap.Host)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		run, err := nmap.Parse(data)
		if err != nil {
			log.Printf("[!] Skipping %s due to error: %s", path, err)
			continue
			// return nil, err
		}

		for _, h := range run.Hosts {
			var foundHost nmap.Host
			var foundHostKey string
			ok := false

			for _, ipAddr := range h.Addresses {
				foundHostKey = ipAddr.String()
				foundHost, ok = hostsMap[foundHostKey]
				if ok {
					break
				}
			}

			//if !ok {
			//FIND_BY_HOSTNAME:
			//	for compareHostKey, host := range hostsMap {
			//		for _, hostname := range host.Hostnames {
			//			for _, myHostname := range h.Hostnames {
			//				if myHostname.Name == hostname.Name {
			//					foundHost = host
			//					foundHostKey = compareHostKey
			//					break FIND_BY_HOSTNAME
			//				}
			//			}
			//		}
			//	}
			//}

			if len(foundHost.Addresses) > 0 {
				hostsMap[foundHostKey] = mergeHost(foundHost, h)
			} else {
				// no host found. add new host based on first IP
				hostsMap[h.Addresses[0].String()] = h
			}
		}

		if merged == nil {
			merged = newXMLRun(run)
		} else {
			merged.NmapErrors = append(merged.NmapErrors, run.NmapErrors...)
			merged.PostScripts = append(merged.PostScripts, run.PostScripts...)
			merged.PreScripts = append(merged.PreScripts, run.PreScripts...)
			merged.Targets = append(merged.Targets, run.Targets...)
			merged.TaskBegin = append(merged.TaskBegin, run.TaskBegin...)
			merged.TaskEnd = append(merged.TaskEnd, run.TaskEnd...)
			merged.TaskProgress = append(merged.TaskProgress, run.TaskProgress...)
		}
	}

	if merged == nil {
		return nil, fmt.Errorf("no nmap files merged")
	}

	for _, h := range hostsMap {
		if options.openOnly {
			var ports []nmap.Port
			for _, p := range h.Ports {
				if strings.Contains(p.State.State, "open") {
					ports = append(ports, p)
				}
			}

			if len(ports) == 0 {
				continue
			}

			h.Ports = ports
		}

		sort.Slice(h.Ports, func(i, j int) bool {
			return h.Ports[i].ID < h.Ports[j].ID
		})

		merged.Hosts = append(merged.Hosts, h)

	}

	bytes, err := xml.MarshalIndent(merged, "", "  ")
	if err != nil {
		return nil, err
	}
	bytes = append([]byte(xmlHeader), bytes...)

	return nmap.Parse(bytes)
}

func mergeHost(h1 nmap.Host, h2 nmap.Host) nmap.Host {
	hostnameSet := set.NewSet(nmap.Hostname{})
	hostnameSet.AddRange(h1.Hostnames)
	hostnameSet.AddRange(h2.Hostnames)

	ipSet := set.NewSet(nmap.Address{})
	ipSet.AddRange(h1.Addresses)
	ipSet.AddRange(h2.Addresses)

	status := h1.Status
	if h1.Status.State == "unknown" && h2.Status.State != "unknown" {
		status = h2.Status
	}

	merged := nmap.Host{
		Distance:     h1.Distance,
		EndTime:      h1.EndTime,
		StartTime:    h1.StartTime,
		IPIDSequence: h1.IPIDSequence,
		OS: nmap.OS{
			PortsUsed:    append(h1.OS.PortsUsed, h2.OS.PortsUsed...),
			Matches:      append(h1.OS.Matches, h2.OS.Matches...),
			Fingerprints: append(h1.OS.Fingerprints, h2.OS.Fingerprints...),
		},
		Status:        status,
		TCPSequence:   h1.TCPSequence,
		TCPTSSequence: h1.TCPTSSequence,
		Times:         h1.Times,
		Trace:         h1.Trace,
		Uptime:        h1.Uptime,
		Comment:       h1.Comment,
		Addresses:     ipSet.Slice().([]nmap.Address),
		HostScripts:   append(h1.HostScripts, h2.HostScripts...),
		Smurfs:        append(h1.Smurfs, h2.Smurfs...),
		ExtraPorts:    append(h1.ExtraPorts, h2.ExtraPorts...),
		Hostnames:     hostnameSet.Slice().([]nmap.Hostname),
	}

	start1, _ := strconv.ParseInt(h1.StartTime.FormatTime(), 10, 64)
	start2, _ := strconv.ParseInt(h2.StartTime.FormatTime(), 10, 64)

	if start2 > start1 {
		merged.StartTime = h2.StartTime
		merged.EndTime = h2.EndTime
	}

	tcpPortMap := make(map[uint16]nmap.Port)
	udpPortMap := make(map[uint16]nmap.Port)
	for _, port := range h1.Ports {
		if strings.EqualFold(port.Protocol, "tcp") {
			tcpPortMap[port.ID] = port
		} else {
			udpPortMap[port.ID] = port
		}
	}

	for _, port := range h2.Ports {
		var portMap map[uint16]nmap.Port
		if strings.EqualFold(port.Protocol, "tcp") {
			portMap = tcpPortMap
		} else {
			portMap = udpPortMap
		}

		foundPort, ok := portMap[port.ID]
		if !ok || start2 > start1 { // If not found or if h2 started after h1
			portMap[port.ID] = port
			continue
		}

		portMap[port.ID] = mergePort(foundPort, port)
	}

	for _, p := range tcpPortMap {
		merged.Ports = append(merged.Ports, p)
	}

	for _, p := range udpPortMap {
		merged.Ports = append(merged.Ports, p)
	}

	return merged
}

func hasServiceInfo(svc nmap.Service) bool {
	return svc.Method == "probed" || svc.Product != "" || svc.Version != "" || svc.ExtraInfo != ""
}

func mostAccurateService(s1 nmap.Service, s2 nmap.Service) nmap.Service {
	s1SvcInfo := hasServiceInfo(s1)
	s2SvcInfo := hasServiceInfo(s2)

	if s1SvcInfo && !s2SvcInfo {
		return s1
	}

	if !s1SvcInfo && s2SvcInfo ||
		s1SvcInfo && s2SvcInfo && s2.Confidence > s1.Confidence {
		return s2
	}

	return s1
}

func mergePort(p1 nmap.Port, p2 nmap.Port) nmap.Port {
	p1Closed := p1.State.State == "closed"
	p2Closed := p2.State.State == "closed"
	if !p1Closed && p2Closed {
		return p1
	}

	if p1Closed && !p2Closed {
		return p2
	}

	svc := mostAccurateService(p1.Service, p2.Service)
	return nmap.Port{
		ID:       p1.ID,
		Protocol: p1.Protocol,
		Owner:    p1.Owner,
		Service:  svc,
		State:    p1.State,
		Scripts:  append(p1.Scripts, p2.Scripts...),
	}
}
