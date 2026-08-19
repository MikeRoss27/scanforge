package report

import (
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ParseNmapCollection parses either a single nmap XML file or a directory of
// per-host XML files (the nmap module's collection layout).
func ParseNmapCollection(path string, report *Report) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var paths []string
	if info.IsDir() {
		err = filepath.WalkDir(path, func(candidate string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".xml") {
				paths = append(paths, candidate)
			}
			return nil
		})
	} else {
		paths = []string{path}
	}
	if err != nil {
		return err
	}
	for _, xmlPath := range paths {
		if err := parseNmapXML(xmlPath, report); err != nil {
			return err
		}
	}
	return nil
}

func parseNmapXML(path string, report *Report) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var result struct {
		Hosts []struct {
			Addresses []struct {
				Addr string `xml:"addr,attr"`
				Type string `xml:"addrtype,attr"`
			} `xml:"address"`
			Hostnames []struct {
				Name string `xml:"name,attr"`
			} `xml:"hostnames>hostname"`
			Ports []struct {
				ID       int    `xml:"portid,attr"`
				Protocol string `xml:"protocol,attr"`
				State    struct {
					Value string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
			} `xml:"ports>port"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(data, &result); err != nil {
		return err
	}
	for _, host := range result.Hosts {
		name := ""
		if len(host.Hostnames) > 0 {
			name = normalizeAssetName(host.Hostnames[0].Name)
		}
		for _, address := range host.Addresses {
			if name == "" && (address.Type == "ipv4" || address.Type == "ipv6") {
				name = address.Addr
			}
		}
		if name == "" {
			continue
		}
		asset := report.GetOrCreateAsset(name)
		for _, address := range host.Addresses {
			if address.Type == "ipv4" || address.Type == "ipv6" {
				asset.IPs = appendUnique(asset.IPs, address.Addr)
			}
		}
		for _, port := range host.Ports {
			if port.State.Value != "open" {
				continue
			}
			asset.Ports[port.ID] = &Port{
				Number: port.ID, Protocol: port.Protocol, Service: port.Service.Name,
				Product: port.Service.Product, Version: port.Service.Version,
			}
		}
	}
	return nil
}
