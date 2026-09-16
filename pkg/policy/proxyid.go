// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"strconv"
	"strings"
)

// ProxyStatsKey returns a key for endpoint's proxy stats, which may aggregate stats from multiple
// proxy redirects on the same port.
func ProxyStatsKey(ingress bool, protocol string, port, proxyPort uint16) string {
	var buf [64]byte
	b := buf[:0]
	if ingress {
		b = append(b, "ingress:"...)
	} else {
		b = append(b, "egress:"...)
	}
	b = append(b, protocol...)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(port), 10)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(proxyPort), 10)

	return string(b)
}

// ProxyID returns a unique string to identify a proxy mapping.
func ProxyID(endpointID uint16, ingress bool, protocol string, port uint16, listener string) string {
	var buf [128]byte
	b := buf[:0]
	b = strconv.AppendUint(b, uint64(endpointID), 10)
	b = append(b, ':')
	if ingress {
		b = append(b, "ingress:"...)
	} else {
		b = append(b, "egress:"...)
	}
	b = append(b, protocol...)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(port), 10)
	b = append(b, ':')
	b = append(b, listener...)

	return string(b)
}

// ParseProxyID parses a proxy ID returned by ProxyID and returns its components.
func ParseProxyID(proxyID string) (endpointID uint16, ingress bool, protocol string, port uint16, listener string, err error) {
	epStr, rest, ok := strings.Cut(proxyID, ":")
	if !ok {
		return 0, false, "", 0, "", fmt.Errorf("invalid proxy ID structure: %s", proxyID)
	}
	dirStr, rest, ok := strings.Cut(rest, ":")
	if !ok {
		return 0, false, "", 0, "", fmt.Errorf("invalid proxy ID structure: %s", proxyID)
	}
	protoStr, rest, ok := strings.Cut(rest, ":")
	if !ok {
		return 0, false, "", 0, "", fmt.Errorf("invalid proxy ID structure: %s", proxyID)
	}
	portStr, listenerStr, ok := strings.Cut(rest, ":")
	if !ok || strings.IndexByte(listenerStr, ':') >= 0 {
		return 0, false, "", 0, "", fmt.Errorf("invalid proxy ID structure: %s", proxyID)
	}

	epID, err := strconv.ParseUint(epStr, 10, 16)
	if err != nil {
		return 0, false, "", 0, "", err
	}
	l4port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, false, "", 0, "", err
	}

	return uint16(epID), dirStr == "ingress", protoStr, uint16(l4port), listenerStr, nil
}
