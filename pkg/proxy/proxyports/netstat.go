// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxyports

import (
	"bytes"
	"os"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var (
	// procNetFiles is the constant map showing the correspondance of /proc/net files
	// to the bool flag of the "do we expect them to be present based on the config"
	// /proc/net files may be used to get the information about open connections as output by netstat.
	procNetFiles = map[string]bool{
		"/proc/net/tcp":  option.Config.EnableIPv4,
		"/proc/net/udp":  option.Config.EnableIPv4,
		"/proc/net/tcp6": option.Config.EnableIPv6,
		"/proc/net/udp6": option.Config.EnableIPv6,
	}
)

// GetOpenLocalPorts returns the set of L4 ports currently open locally.
func (p *ProxyPorts) GetOpenLocalPorts() map[uint16]struct{} {
	openLocalPorts := make(map[uint16]struct{}, 128)

	for file, enabled := range procNetFiles {
		b, err := os.ReadFile(file)
		if err != nil {
			// we only need to report this as unexpected behaviour
			// when the ipvX is enabled in the config, but not present as a file
			if enabled {
				p.logger.Error("cannot read proc file",
					logfields.Path, file,
					logfields.Error, err,
				)
			}

			continue
		}

		// Extract the local port number from the "local_address" column.
		// The header line won't match and will be ignored.
		for len(b) > 0 {
			line := b
			if idx := bytes.IndexByte(b, '\n'); idx >= 0 {
				line = b[:idx]
				b = b[idx+1:]
			} else {
				b = nil
			}
			if port, ok := parseProcNetPort(line); ok {
				openLocalPorts[port] = struct{}{}
			}
		}
	}

	return openLocalPorts
}

func parseProcNetPort(line []byte) (uint16, bool) {
	i := 0
	for i < len(line) && line[i] == ' ' {
		i++
	}
	if i >= len(line) || line[i] < '0' || line[i] > '9' {
		return 0, false
	}
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	if i >= len(line) || line[i] != ':' {
		return 0, false
	}
	i++
	for i < len(line) && line[i] == ' ' {
		i++
	}
	ipStart := i
	for i < len(line) && isHex(line[i]) {
		i++
	}
	if i == ipStart || i >= len(line) || line[i] != ':' {
		return 0, false
	}
	i++
	var port uint16
	portStart := i
	for i < len(line) && isHex(line[i]) {
		val := hexVal(line[i])
		port = (port << 4) | uint16(val)
		i++
	}
	if i == portStart || i >= len(line) || line[i] != ' ' {
		return 0, false
	}
	return port, true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}
