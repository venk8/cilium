// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"net/netip"
	"testing"

	"github.com/cilium/statedb/index"
	"github.com/stretchr/testify/require"
)

func TestNeighborID_Key(t *testing.T) {
	id := NeighborID{
		LinkIndex: 5,
		IPAddr:    netip.MustParseAddr("10.0.0.1"),
	}
	key := id.Key()
	require.Len(t, key, neighborIndexSize)

	parsed, err := neighborIDIndex.FromString("5:10.0.0.1")
	require.NoError(t, err)
	require.Equal(t, index.Key(key), parsed)

	// IPv6 test
	id6 := NeighborID{
		LinkIndex: 12,
		IPAddr:    netip.MustParseAddr("fd00::2"),
	}
	key6 := id6.Key()
	require.Len(t, key6, neighborIndexSize)
	parsed6, err := neighborIDIndex.FromString("12:fd00::2")
	require.NoError(t, err)
	require.Equal(t, index.Key(key6), parsed6)
}

func BenchmarkNeighborID_Key(b *testing.B) {
	id := NeighborID{
		LinkIndex: 5,
		IPAddr:    netip.MustParseAddr("10.0.0.1"),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = id.Key()
	}
}

func BenchmarkNeighborIDFromString(b *testing.B) {
	s := "5:10.0.0.1"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = neighborIDIndex.FromString(s)
	}
}

func BenchmarkNeighborState_String(b *testing.B) {
	s := NeighborState(NUD_REACHABLE | NUD_STALE | NUD_PERMANENT)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.String()
	}
}

func BenchmarkNeighborFlags_String(b *testing.B) {
	f := NeighborFlags(NTF_SELF | NTF_ROUTER | NTF_EXT_LEARNED)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.String()
	}
}

func BenchmarkNeighborType_String(b *testing.B) {
	t := NDA_DST
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = t.String()
	}
}

func BenchmarkNeighbor_TableRow(b *testing.B) {
	n := &Neighbor{
		LinkIndex:    10,
		IPAddr:       netip.MustParseAddr("192.168.1.1"),
		HardwareAddr: HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		Type:         NDA_DST,
		State:        NUD_REACHABLE | NUD_STALE,
		Flags:        NTF_SELF,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = n.TableRow()
	}
}

