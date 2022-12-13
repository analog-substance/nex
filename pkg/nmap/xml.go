package nmap

import (
	"encoding/xml"
	"fmt"
	"os"
	"strconv"

	"github.com/Ullaakut/nmap/v2"
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

func XMLMerge(paths []string) (*nmap.Run, error) {
	var merged *nmap.Run
	hostsMap := make(map[string]nmap.Host)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		run, err := nmap.Parse(data)
		if err != nil {
			return nil, err
		}

		if merged == nil {
			merged = newXMLRun(run)
		}

		for _, h := range run.Hosts {
			ip := h.Addresses[0].String()
			foundHost, ok := hostsMap[ip]
			if !ok {
				hostsMap[ip] = h
			} else {
				hostsMap[ip] = mergeHost(foundHost, h)
			}
		}
	}

	if merged == nil {
		return nil, nil
	}

	for _, h := range hostsMap {
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
		Status:        h1.Status,
		TCPSequence:   h1.TCPSequence,
		TCPTSSequence: h1.TCPTSSequence,
		Times:         h1.Times,
		Trace:         h1.Trace,
		Uptime:        h1.Uptime,
		Comment:       h1.Comment,
		Addresses:     h1.Addresses,
		HostScripts:   append(h1.HostScripts, h2.HostScripts...),
		Smurfs:        append(h1.Smurfs, h2.Smurfs...),
		ExtraPorts:    append(h1.ExtraPorts, h2.ExtraPorts...),
		Hostnames:     append(h1.Hostnames, h2.Hostnames...),
	}

	start1, _ := strconv.ParseInt(h1.StartTime.FormatTime(), 10, 64)
	start2, _ := strconv.ParseInt(h2.StartTime.FormatTime(), 10, 64)

	if start2 > start1 {
		merged.StartTime = h2.StartTime
		merged.EndTime = h2.EndTime
	}

	hasServiceInfo := func(svc nmap.Service) bool {
		return svc.Product != "" || svc.Version != "" || svc.ExtraInfo != ""
	}

	portMap := make(map[uint16]nmap.Port)
	allPorts := append(h1.Ports, h2.Ports...)
	for _, port := range allPorts {
		foundPort, ok := portMap[port.ID]
		if !ok {
			portMap[port.ID] = port
			continue
		}

		// If any of these aren't empty, more than likely it means a service scan was done
		// which is more accurate
		if hasServiceInfo(foundPort.Service) {
			continue
		}

		if hasServiceInfo(port.Service) {
			portMap[port.ID] = port
			continue
		}

		// Use most recent one?
		if start2 > start1 {
			portMap[port.ID] = port
		}
	}

	for _, p := range portMap {
		merged.Ports = append(merged.Ports, p)
	}

	return merged
}
