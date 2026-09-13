// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/cilium/cilium/api/v1/models"
)

type IPListEntrySlice []*models.IPListEntry

// CompareIPListEntry compares two IPListEntry objects by CIDR prefix length then IP address.
func CompareIPListEntry(a, b *models.IPListEntry) int {
	aNet, _ := netip.ParsePrefix(*a.Cidr)
	bNet, _ := netip.ParsePrefix(*b.Cidr)
	if c := cmp.Compare(aNet.Bits(), bNet.Bits()); c != 0 {
		return c
	}
	return aNet.Addr().Compare(bNet.Addr())
}

// Sort sorts the IPListEntry objects in-place using generic slices.SortFunc.
func (s IPListEntrySlice) Sort() {
	slices.SortFunc(s, CompareIPListEntry)
}

func (s IPListEntrySlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less sorts the IPListEntry objects by CIDR prefix then IP address.
// Given that the same IP cannot map to more than one identity, no further
// sorting is performed.
func (s IPListEntrySlice) Less(i, j int) bool {
	iNet, _ := netip.ParsePrefix(*s[i].Cidr)
	jNet, _ := netip.ParsePrefix(*s[j].Cidr)
	iPrefixSize := iNet.Bits()
	jPrefixSize := jNet.Bits()
	if iPrefixSize == jPrefixSize {
		return iNet.Addr().Less(jNet.Addr())
	}
	return iPrefixSize < jPrefixSize
}

func (s IPListEntrySlice) Len() int {
	return len(s)
}
