package nmap

import (
	"encoding/xml"
	"fmt"
	"os"

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
	var all *nmap.Run
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		run, err := nmap.Parse(data)
		if err != nil {
			return nil, err
		}

		if all == nil {
			all = run
			continue
		}

		for _, h := range run.Hosts {
			all.Hosts = append(all.Hosts, h)
		}
	}

	bytes, err := xml.MarshalIndent(all, "", "  ")
	if err != nil {
		return nil, err
	}
	bytes = append([]byte(xmlHeader), bytes...)

	return nmap.Parse(bytes)
}
