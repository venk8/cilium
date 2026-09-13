// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lxcmap

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/mac"
)

func TestEndpointKey(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.1")
	k4 := newEndpointKey(v4)
	require.Equal(t, v4, k4.ToAddr())
	require.Contains(t, k4.String(), "10.0.0.1:0")

	v6 := netip.MustParseAddr("fd00::1")
	k6 := newEndpointKey(v6)
	require.Equal(t, v6, k6.ToAddr())
	require.Contains(t, k6.String(), "fd00::1:0")

	kNew := k4.New()
	require.IsType(t, &EndpointKey{}, kNew)
}

func TestEndpointInfo(t *testing.T) {
	info := &EndpointInfo{
		Flags: EndpointFlagHost,
	}
	require.True(t, info.IsHost())
	require.Equal(t, "(localhost)", info.String())

	info2 := &EndpointInfo{
		LxcID:         123,
		SecID:         456,
		Flags:         EndpointFlagAtHostNS,
		IfIndex:       5,
		MAC:           mac.MAC{1, 2, 3, 4, 5, 6},
		NodeMAC:       mac.MAC{6, 5, 4, 3, 2, 1},
		ParentIfIndex: 2,
		RTInfo:        7,
	}
	require.False(t, info2.IsHost())
	s := info2.String()
	require.Contains(t, s, "id=123")
	require.Contains(t, s, "sec_id=456")

	vNew := info.New()
	require.IsType(t, &EndpointInfo{}, vNew)
}

func BenchmarkEndpointKey_NewIPv4(b *testing.B) {
	addr := netip.MustParseAddr("10.0.0.1")
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = newEndpointKey(addr)
	}
}

func BenchmarkEndpointKey_NewIPv6(b *testing.B) {
	addr := netip.MustParseAddr("fd00::1")
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = newEndpointKey(addr)
	}
}

func BenchmarkEndpointInfo_String(b *testing.B) {
	info := &EndpointInfo{
		LxcID:         123,
		SecID:         456,
		Flags:         EndpointFlagAtHostNS,
		IfIndex:       5,
		MAC:           mac.MAC{1, 2, 3, 4, 5, 6},
		NodeMAC:       mac.MAC{6, 5, 4, 3, 2, 1},
		ParentIfIndex: 2,
		RTInfo:        7,
	}
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = info.String()
	}
}
