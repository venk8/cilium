// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbor

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDesiredNeighborKey(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.50")
	key := DesiredNeighborKey{
		IP:      ip,
		IfIndex: 42,
	}

	tableKey := key.TableKey()
	require.Len(t, tableKey, 20)

	str := key.String()
	require.Equal(t, "192.168.1.50@42", str)

	parsedKey, err := desiredNeighborKeyFromString(str)
	require.NoError(t, err)
	require.Equal(t, tableKey, parsedKey)

	// IPv6 test
	ip6 := netip.MustParseAddr("fd00::1")
	key6 := DesiredNeighborKey{
		IP:      ip6,
		IfIndex: 10,
	}
	tableKey6 := key6.TableKey()
	require.Len(t, tableKey6, 20)
	str6 := key6.String()
	require.Equal(t, "fd00::1@10", str6)
	parsedKey6, err := desiredNeighborKeyFromString(str6)
	require.NoError(t, err)
	require.Equal(t, tableKey6, parsedKey6)
}

func TestForwardableIPOwnerString(t *testing.T) {
	ownerNode := ForwardableIPOwner{Type: ForwardableIPOwnerNode, ID: "node-xyz"}
	require.Equal(t, "node:node-xyz", ownerNode.String())

	ownerSvc := ForwardableIPOwner{Type: ForwardableIPOwnerService, ID: "svc-abc"}
	require.Equal(t, "service:svc-abc", ownerSvc.String())
}

func BenchmarkDesiredNeighborKey_TableKey(b *testing.B) {
	key := DesiredNeighborKey{
		IP:      netip.MustParseAddr("192.168.1.50"),
		IfIndex: 42,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = key.TableKey()
	}
}

func BenchmarkDesiredNeighborKey_String(b *testing.B) {
	key := DesiredNeighborKey{
		IP:      netip.MustParseAddr("192.168.1.50"),
		IfIndex: 42,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = key.String()
	}
}

func BenchmarkDesiredNeighborKeyFromString(b *testing.B) {
	s := "192.168.1.50@42"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = desiredNeighborKeyFromString(s)
	}
}

func BenchmarkForwardableIPOwner_String(b *testing.B) {
	owner := ForwardableIPOwner{
		Type: ForwardableIPOwnerNode,
		ID:   "node-xyz",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = owner.String()
	}
}
