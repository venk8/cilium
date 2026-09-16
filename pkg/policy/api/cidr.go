// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"strings"

	"github.com/cilium/cilium/pkg/labels"
)

// CIDR specifies a block of IP addresses.
// Example: 192.0.2.1/32
//
// +kubebuilder:validation:Format=cidr
type CIDR string

func (s CIDR) SelectorKey() string {
	return labels.LabelSourceCIDR + ":" + string(s)
}

// CIDRRule is a rule that specifies a CIDR prefix to/from which outside
// communication  is allowed, along with an optional list of subnets within that
// CIDR prefix to/from which outside communication is not allowed.
type CIDRRule struct {
	// CIDR is a CIDR prefix / IP Block.
	//
	// +kubebuilder:validation:OneOf
	Cidr CIDR `json:"cidr,omitempty"`

	// CIDRGroupRef is a reference to a CiliumCIDRGroup object.
	// A CiliumCIDRGroup contains a list of CIDRs that the endpoint, subject to
	// the rule, can (Ingress/Egress) or cannot (IngressDeny/EgressDeny) receive
	// connections from.
	//
	// +kubebuilder:validation:OneOf
	CIDRGroupRef CIDRGroupRef `json:"cidrGroupRef,omitempty"`

	// CIDRGroupSelector selects CiliumCIDRGroups by their labels,
	// rather than by name.
	//
	// +kubebuilder:validation:OneOf
	CIDRGroupSelector EndpointSelector `json:"cidrGroupSelector,omitzero"`

	// ExceptCIDRs is a list of IP blocks which the endpoint subject to the rule
	// is not allowed to initiate connections to. These CIDR prefixes should be
	// contained within Cidr, using ExceptCIDRs together with CIDRGroupRef is not
	// supported yet.
	// These exceptions are only applied to the Cidr in this CIDRRule, and do not
	// apply to any other CIDR prefixes in any other CIDRRules.
	//
	// +kubebuilder:validation:Optional
	ExceptCIDRs []CIDR `json:"except,omitempty"`

	// Generated indicates whether the rule was generated based on other rules
	// or provided by user
	Generated bool `json:"-"`
}

func (r CIDRRule) SelectorKey() string {
	return r.String()
}

// String converts the CIDRRule into a human-readable string.
func (r CIDRRule) String() string {
	var key string
	switch {
	case r.CIDRGroupRef != "":
		key = r.CIDRGroupRef.SelectorKey()
	case r.CIDRGroupSelector.LabelSelector != nil:
		key = r.CIDRGroupSelector.SelectorKey()
	default:
		key = r.Cidr.SelectorKey()
	}
	if len(r.ExceptCIDRs) == 0 {
		return key
	}
	return key + "-" + CIDRSlice(r.ExceptCIDRs).String()
}

// CIDRSlice is a slice of CIDRs. It allows receiver methods to be defined for
// transforming the slice into other convenient forms such as
// EndpointSelectorSlice.
type CIDRSlice []CIDR

// GetAsEndpointSelectors returns the provided CIDR slice as a slice of
// endpoint selectors
func (s CIDRSlice) GetAsEndpointSelectors() EndpointSelectorSlice {
	slice := EndpointSelectorSlice{}
	for _, cidr := range s {
		lbl, err := labels.IPStringToLabel(string(cidr))
		if err == nil {
			slice = append(slice, NewESFromLabels(lbl))
		}
	}

	return slice
}

// StringSlice returns the CIDR slice as a slice of strings.
func (s CIDRSlice) StringSlice() []string {
	result := make([]string, 0, len(s))
	for _, c := range s {
		result = append(result, string(c))
	}
	return result
}

// String converts the CIDRSlice into a human-readable string.
func (s CIDRSlice) String() string {
	if len(s) == 0 {
		return ""
	}
	total := 1 + len(s)
	for _, c := range s {
		total += len(c)
	}
	if total <= 64 {
		var buf [64]byte
		buf[0] = '['
		n := 1
		for i, c := range s {
			if i > 0 {
				buf[n] = ','
				n++
			}
			n += copy(buf[n:], c)
		}
		buf[n] = ']'
		n++
		return string(buf[:n])
	}
	var b strings.Builder
	b.Grow(total)
	b.WriteByte('[')
	for i, c := range s {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(string(c))
	}
	b.WriteByte(']')
	return b.String()
}

// CIDRRuleSlice is a slice of CIDRRules. It allows receiver methods to be
// defined for transforming the slice into other convenient forms such as
// EndpointSelectorSlice.
type CIDRRuleSlice []CIDRRule

// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
//
// CIDRGroupRef is a reference to a CIDR Group.
// A CIDR Group is a list of CIDRs whose IP addresses should be considered as a
// same entity when applying fromCIDRGroupRefs policies on incoming network traffic.
type CIDRGroupRef string

func (c CIDRGroupRef) SelectorKey() string {
	return labels.LabelSourceCIDRGroup + ":" + LabelPrefixGroupName + "/" + string(c)
}

const LabelPrefixGroupName = "io.cilium.policy.cidrgroupname"

func LabelForCIDRGroupRef(ref string) labels.Label {
	return labels.NewLabel(
		LabelPrefixGroupName+"/"+ref,
		"",
		labels.LabelSourceCIDRGroup,
	)
}

