// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"net/netip"
	"testing"

	"github.com/cilium/statedb/index"
	"github.com/stretchr/testify/require"
)

func TestRouteID_Key(t *testing.T) {
	id := RouteID{
		Table:     RouteTable(254),
		LinkIndex: 2,
		Dst:       netip.MustParsePrefix("10.0.0.0/24"),
	}
	key := id.Key()
	require.Len(t, key, 25)

	parsed, err := routeIDIndex.FromString("254:2:10.0.0.0/24")
	require.NoError(t, err)
	require.Equal(t, index.Key(key), parsed)

	// Short prefix keys
	idTableOnly := RouteID{Table: RouteTable(254)}
	keyTableOnly := idTableOnly.Key()
	require.Len(t, keyTableOnly, 4)

	idLinkOnly := RouteID{Table: RouteTable(254), LinkIndex: 2}
	keyLinkOnly := idLinkOnly.Key()
	require.Len(t, keyLinkOnly, 8)
}

func BenchmarkRouteID_Key(b *testing.B) {
	id := RouteID{
		Table:     RouteTable(254),
		LinkIndex: 2,
		Dst:       netip.MustParsePrefix("10.0.0.0/24"),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = id.Key()
	}
}

func BenchmarkRouteID_Key_TableOnly(b *testing.B) {
	id := RouteID{
		Table: RouteTable(254),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = id.Key()
	}
}

func BenchmarkRouteIDFromString(b *testing.B) {
	s := "254:2:10.0.0.0/24"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = routeIDIndex.FromString(s)
	}
}
