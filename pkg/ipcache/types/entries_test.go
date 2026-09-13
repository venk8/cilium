// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"
)

func TestIPListEntrySliceSwap(t *testing.T) {
	entries := IPListEntrySlice{
		{Cidr: strPtr("192.168.1.1/32")},
		{Cidr: strPtr("10.0.0.1/32")},
	}
	entries.Swap(0, 1)
	if *entries[0].Cidr != "10.0.0.1/32" || *entries[1].Cidr != "192.168.1.1/32" {
		t.Errorf("Swap did not swap elements correctly")
	}
}

func TestIPListEntrySliceLess(t *testing.T) {
	entries := IPListEntrySlice{
		{Cidr: strPtr("192.168.1.1/32")},
		{Cidr: strPtr("10.0.0.1/32")},
	}
	if !entries.Less(1, 0) {
		t.Errorf("Expected 10.0.0.1/32 to be less than 192.168.1.1/32")
	}
}

func TestIPListEntrySliceLen(t *testing.T) {
	entries := IPListEntrySlice{
		{Cidr: strPtr("192.168.1.1/32")},
		{Cidr: strPtr("10.0.0.1/32")},
	}
	if entries.Len() != 2 {
		t.Errorf("Expected length 2, got %d", entries.Len())
	}
}

func TestIPListEntrySliceSort(t *testing.T) {
	entries := IPListEntrySlice{
		{Cidr: strPtr("192.168.1.1/32")},
		{Cidr: strPtr("10.0.0.0/8")},
		{Cidr: strPtr("172.16.0.0/16")},
		{Cidr: strPtr("10.0.0.1/32")},
	}
	entries.Sort()
	expected := []string{
		"10.0.0.0/8",
		"172.16.0.0/16",
		"10.0.0.1/32",
		"192.168.1.1/32",
	}
	for i, e := range entries {
		if *e.Cidr != expected[i] {
			t.Errorf("Index %d: expected %s, got %s", i, expected[i], *e.Cidr)
		}
	}
}

// Helper function to create *string from string
func strPtr(s string) *string {
	return &s
}
