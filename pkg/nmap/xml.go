package nmap

import (
	"encoding/xml"
	"os"
	"path/filepath"

	"github.com/Ullaakut/nmap/v2"
)

func XMLToHosts(path string) error {
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

		nmapPath := filepath.Join(currentHost.Dir, "recon", "nmap-punched-tcp.xml")
		err = os.WriteFile(nmapPath, bytes, 0644)
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
