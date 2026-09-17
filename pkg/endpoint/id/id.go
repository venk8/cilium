// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package id

import (
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
)

// MaxEndpointID is the maximum endpoint identifier.
const MaxEndpointID = math.MaxUint16

// PrefixType describes the type of endpoint identifier
type PrefixType string

func (s PrefixType) String() string { return string(s) }

const (
	// CiliumLocalIdPrefix is a numeric identifier with local scope. It has
	// no cluster wide meaning and is only unique in the scope of a single
	// agent. An endpoint is guaranteed to always have a local scope identifier.
	CiliumLocalIdPrefix PrefixType = "cilium-local"

	// CiliumGlobalIdPrefix is an endpoint identifier with global scope.
	// This addressing mechanism is currently unused.
	CiliumGlobalIdPrefix PrefixType = "cilium-global"

	// CNIAttachmentIdPrefix is used to address an endpoint via its primary
	// container ID and container interface passed to the CNI plugin.
	// This attachment ID uniquely identifies a CNI ADD and CNI DEL invocation pair.
	CNIAttachmentIdPrefix PrefixType = "cni-attachment-id"

	// CEPNamePrefix is used to address an endpoint via its Kubernetes
	// CiliumEndpoint resource name. This addressing only works if the endpoint
	// is represented as a Kubernetes CiliumEndpoint resource.
	CEPNamePrefix PrefixType = "cep-name"

	// IPv4Prefix is used to address an endpoint via the endpoint's IPv4
	// address.
	IPv4Prefix PrefixType = "ipv4"

	// IPv6Prefix is the prefix used to refer to an endpoint via IPv6 address
	IPv6Prefix PrefixType = "ipv6"
)

// NewCiliumID returns a new endpoint identifier of type CiliumLocalIdPrefix
func NewCiliumID(id int64) string {
	var buf [32]byte
	b := append(buf[:0], CiliumLocalIdPrefix...)
	b = append(b, ':')
	b = strconv.AppendInt(b, id, 10)
	return string(b)
}

// NewID returns a new endpoint identifier
func NewID(prefix PrefixType, id string) string {
	return string(prefix) + ":" + id
}

// NewIPPrefixID returns an identifier based on the IP address specified. If ip
// is invalid, an empty string is returned.
func NewIPPrefixID(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	var buf [64]byte
	b := buf[:0]
	if ip.Is6() {
		b = append(b, IPv6Prefix...)
	} else {
		b = append(b, IPv4Prefix...)
	}
	b = append(b, ':')
	b = ip.AppendTo(b)
	return string(b)
}

// NewCNIAttachmentID returns an identifier based on the CNI attachment ID. If
// the containerIfName is empty, only the containerID will be used.
func NewCNIAttachmentID(containerID, containerIfName string) string {
	if containerIfName == "" {
		return NewID(CNIAttachmentIdPrefix, containerID)
	}
	var buf [128]byte
	b := append(buf[:0], CNIAttachmentIdPrefix...)
	b = append(b, ':')
	b = append(b, containerID...)
	b = append(b, ':')
	b = append(b, containerIfName...)
	return string(b)
}

// splitID splits ID into prefix and id. No validation is performed on prefix.
func splitID(id string) (PrefixType, string) {
	if before, after, found := strings.Cut(id, ":"); found {
		return PrefixType(before), after
	}

	// default prefix
	return CiliumLocalIdPrefix, id
}

// ParseCiliumID parses id as cilium endpoint id and returns numeric portion.
func ParseCiliumID(id string) (int64, error) {
	prefix, id := splitID(id)
	if prefix != CiliumLocalIdPrefix {
		return 0, fmt.Errorf("not a cilium identifier")
	}
	n, err := strconv.ParseInt(id, 0, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid numeric cilium id: %w", err)
	}
	if n > MaxEndpointID {
		return 0, fmt.Errorf("endpoint id too large: %d", n)
	}
	return n, nil
}

// Parse parses a string as an endpoint identified consists of an optional
// prefix [prefix:] followed by the identifier.
func Parse(id string) (PrefixType, string, error) {
	prefix, id := splitID(id)
	switch prefix {
	case CiliumLocalIdPrefix,
		CiliumGlobalIdPrefix,
		CNIAttachmentIdPrefix,
		CEPNamePrefix,
		IPv4Prefix,
		IPv6Prefix:
		return prefix, id, nil
	}

	return "", "", fmt.Errorf("unknown endpoint ID prefix \"%s\"", prefix)
}
