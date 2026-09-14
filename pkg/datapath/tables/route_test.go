// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
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

func BenchmarkRoute_TableRow(b *testing.B) {
	r := &Route{
		Table:     RT_TABLE_MAIN,
		LinkIndex: 5,
		Type:      RTN_UNICAST,
		Scope:     RT_SCOPE_UNIVERSE,
		Dst:       netip.MustParsePrefix("10.0.0.0/24"),
		Src:       netip.MustParseAddr("10.0.0.1"),
		Gw:        netip.MustParseAddr("10.0.0.254"),
		Priority:  100,
		MTU:       1500,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.TableRow()
	}
}

func BenchmarkRouteTable_String(b *testing.B) {
	t := RouteTable(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = t.String()
	}
}

func BenchmarkHasDefaultRoute(b *testing.B) {
	db := statedb.New()
	tbl, err := NewRouteTable(db)
	if err != nil {
		b.Fatal(err)
	}
	wtxn := db.WriteTxn(tbl)
	tbl.Insert(wtxn, &Route{
		Table:     RT_TABLE_MAIN,
		LinkIndex: 2,
		Dst:       zeroPrefixV4,
	})
	wtxn.Commit()

	rxn := db.ReadTxn()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HasDefaultRoute(tbl, rxn, 2)
	}
}

