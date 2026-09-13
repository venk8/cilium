// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fragmap

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/types"
)

func TestFragment_Strings(t *testing.T) {
	k4 := &FragmentKey4{
		DestAddr:   types.IPv4(netip.MustParseAddr("10.0.0.2").As4()),
		SourceAddr: types.IPv4(netip.MustParseAddr("10.0.0.1").As4()),
		ID:         0x3412,
		Proto:      6,
	}
	assert.Contains(t, k4.String(), "10.0.0.1 --> 10.0.0.2, 6, ")

	v4 := &FragmentValue4{DestPort: 80, SourcePort: 12345}
	assert.Equal(t, "80, 12345", v4.String())

	k6 := &FragmentKey6{
		DestAddr:   types.IPv6(netip.MustParseAddr("fd00::2").As16()),
		SourceAddr: types.IPv6(netip.MustParseAddr("fd00::1").As16()),
		ID:         0x78563412,
		Proto:      6,
	}
	assert.Contains(t, k6.String(), "fd00::1 --> fd00::2, 6, ")

	v6 := &FragmentValue6{DestPort: 443, SourcePort: 54321}
	assert.Equal(t, "443, 54321", v6.String())
}

func BenchmarkFragmentKey4_String(b *testing.B) {
	k4 := &FragmentKey4{
		DestAddr:   types.IPv4(netip.MustParseAddr("10.0.0.2").As4()),
		SourceAddr: types.IPv4(netip.MustParseAddr("10.0.0.1").As4()),
		ID:         0x3412,
		Proto:      6,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k4.String()
	}
}

func BenchmarkFragmentKey6_String(b *testing.B) {
	k6 := &FragmentKey6{
		DestAddr:   types.IPv6(netip.MustParseAddr("fd00::2").As16()),
		SourceAddr: types.IPv6(netip.MustParseAddr("fd00::1").As16()),
		ID:         0x78563412,
		Proto:      6,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k6.String()
	}
}
