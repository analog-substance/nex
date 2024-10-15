package nmap

import (
	"github.com/Ullaakut/nmap/v2"
	"github.com/analog-substance/arsenic/pkg/host"
	"os"
	"path/filepath"
	"strings"
)

func getHost(hostnames []string, ips []string) (*host.Host, error) {
	var err error

	currentHost := host.GetFirst(append(hostnames, ips...)...)
	if currentHost == nil {
		currentHost, err = host.AddHost(hostnames, ips)
		if err != nil {
			return nil, err
		}
	}
	return currentHost, nil
}

func writeToFile(h *host.Host, name string, data []byte) error {
	path := filepath.Join(h.Dir, "recon", name)
	err := os.WriteFile(path, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

func hasOpenPorts(h nmap.Host) bool {
	for _, p := range h.Ports {
		if strings.Contains(p.State.State, "open") {
			return true
		}
	}
	return false
}

//func timer(name string) func() {
//	start := time.Now()
//	return func() {
//		log.Printf("%s took %v\n", name, time.Since(start))
//	}
//}
