package nmap

import (
	"os"
	"path/filepath"

	"github.com/analog-substance/arsenic/lib/host"
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
