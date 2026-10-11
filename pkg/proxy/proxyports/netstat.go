// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxyports

import (
	"bufio"
	"bytes"
	"math/bits"
	"os"
	"strconv"

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

// portBitmap represents a bitset of all 65536 possible uint16 L4 ports (0 to 65535).
// It occupies 1024 * 8 = 8192 bytes and fits on the stack without heap allocation.
type portBitmap [1024]uint64

func (b *portBitmap) set(port uint16) {
	b[port/64] |= 1 << (port % 64)
}

func (b *portBitmap) get(port uint16) bool {
	return (b[port/64] & (1 << (port % 64))) != 0
}

func (b *portBitmap) toMap() map[uint16]struct{} {
	var count int
	for _, word := range b {
		count += bits.OnesCount64(word)
	}
	m := make(map[uint16]struct{}, count)
	for i, word := range b {
		if word == 0 {
			continue
		}
		base := uint16(i * 64)
		for bit := range 64 {
			if word&(1<<bit) != 0 {
				m[base+uint16(bit)] = struct{}{}
			}
		}
	}
	return m
}

// parseProcNetPort parses a single line from /proc/net/{tcp,udp,tcp6,udp6} and extracts the local port.
// Data lines follow the format: "   sl: local_address rem_address ..." where local_address is "<ip>:<port> ".
// It returns (port, true, nil) on a valid data line, (0, false, nil) for non-data lines (such as the header),
// or (0, true, err) if the line matched the data layout but port parsing failed.
func parseProcNetPort(line []byte) (uint16, bool, error) {
	colon1 := bytes.IndexByte(line, ':')
	if colon1 == -1 {
		return 0, false, nil
	}
	slot := bytes.TrimSpace(line[:colon1])
	if len(slot) == 0 {
		return 0, false, nil
	}
	if _, err := strconv.ParseUint(string(slot), 10, 64); err != nil {
		return 0, false, nil
	}

	rest := bytes.TrimLeft(line[colon1+1:], " ")
	colon2 := bytes.IndexByte(rest, ':')
	if colon2 == -1 {
		return 0, false, nil
	}

	portPart := rest[colon2+1:]
	spaceIdx := bytes.IndexByte(portPart, ' ')
	if spaceIdx == -1 {
		return 0, false, nil
	}

	portHex := portPart[:spaceIdx]
	if len(portHex) == 0 {
		return 0, false, nil
	}

	port, err := strconv.ParseUint(string(portHex), 16, 16)
	if err != nil {
		return 0, true, err
	}
	return uint16(port), true, nil
}

func (p *ProxyPorts) fillOpenLocalPorts(openLocalPorts *portBitmap) {
	var scanBuf [4096]byte
	for file, enabled := range procNetFiles {
		f, err := os.Open(file)
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
		scanner := bufio.NewScanner(f)
		scanner.Buffer(scanBuf[:], len(scanBuf))
		for scanner.Scan() {
			port, ok, err := parseProcNetPort(scanner.Bytes())
			if !ok {
				continue
			}
			if err != nil {
				p.logger.Error("failed to parse port from proc file",
					logfields.Path, file,
					logfields.Error, err,
				)
				continue
			}
			openLocalPorts.set(port)
		}
		f.Close()
	}
}

// GetOpenLocalPorts returns the set of L4 ports currently open locally.
func (p *ProxyPorts) GetOpenLocalPorts() map[uint16]struct{} {
	var openLocalPorts portBitmap
	p.fillOpenLocalPorts(&openLocalPorts)
	return openLocalPorts.toMap()
}
