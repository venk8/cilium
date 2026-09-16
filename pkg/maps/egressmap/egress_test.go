// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
)

func TestCell(t *testing.T) {
	err := hive.New(Cell).Populate(hivetest.Logger(t))
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkEgressPolicyKey4_String(b *testing.B) {
	k := NewEgressPolicyKey4(netip.MustParseAddr("10.0.0.1"), netip.MustParsePrefix("192.168.1.0/24"))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k.String()
	}
}

func BenchmarkEgressPolicyVal4_String(b *testing.B) {
	v := NewEgressPolicyVal4V2(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("192.168.1.1"), 4)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = v.String()
	}
}

func BenchmarkEgressPolicyKey6_String(b *testing.B) {
	k := NewEgressPolicyKey6(netip.MustParseAddr("fd00::1"), netip.MustParsePrefix("2001:db8::/64"))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k.String()
	}
}

func BenchmarkEgressPolicyVal6_String(b *testing.B) {
	v := NewEgressPolicyVal6(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("2001:db8::1"), 4)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = v.String()
	}
}
