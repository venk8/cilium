// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
)

func TestNatEntryDump(t *testing.T) {
	key4 := &NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				Flags: tuple.TUPLE_F_IN,
			},
		},
	}
	entry4 := &NatEntry4{
		Created: 100,
		NeedsCT: 1,
		Addr:    types.IPv4{10, 0, 0, 1},
		Port:    8080,
	}
	toDeltaSecs := func(uint64) string { return "5sec ago" }
	assert.Equal(t, "XLATE_DST 10.0.0.1:8080 Created=5sec ago NeedsCT=1\n", entry4.Dump(key4, toDeltaSecs))
	assert.Equal(t, "Addr=10.0.0.1 Port=8080 Created=100 NeedsCT=1\n", entry4.String())

	key6 := &NatKey6{
		TupleKey6Global: tuple.TupleKey6Global{
			TupleKey6: tuple.TupleKey6{
				Flags: tuple.TUPLE_F_IN,
			},
		},
	}
	ip6 := types.IPv6{}
	ip6[15] = 1
	entry6 := &NatEntry6{
		Created: 100,
		NeedsCT: 1,
		Addr:    ip6,
		Port:    8080,
	}
	assert.Equal(t, "XLATE_DST [::1]:8080 Created=5sec ago NeedsCT=1\n", entry6.Dump(key6, toDeltaSecs))
	assert.Equal(t, "Addr=::1 Port=8080 Created=100 NeedsCT=1\n", entry6.String())
}

func BenchmarkNatEntry4Dump(b *testing.B) {
	key := &NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				Flags: tuple.TUPLE_F_IN,
			},
		},
	}
	entry := &NatEntry4{
		Created: 100,
		NeedsCT: 1,
		Addr:    types.IPv4{10, 0, 0, 1},
		Port:    8080,
	}
	toDeltaSecs := func(t uint64) string { return strconv.FormatUint(t, 10) + "sec ago" }
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = entry.Dump(key, toDeltaSecs)
	}
}

func BenchmarkNatEntry6Dump(b *testing.B) {
	key := &NatKey6{
		TupleKey6Global: tuple.TupleKey6Global{
			TupleKey6: tuple.TupleKey6{
				Flags: tuple.TUPLE_F_IN,
			},
		},
	}
	ip6 := types.IPv6{}
	ip6[15] = 1
	entry := &NatEntry6{
		Created: 100,
		NeedsCT: 1,
		Addr:    ip6,
		Port:    8080,
	}
	toDeltaSecs := func(t uint64) string { return strconv.FormatUint(t, 10) + "sec ago" }
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = entry.Dump(key, toDeltaSecs)
	}
}
