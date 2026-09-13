// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tuple

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestTupleDump(t *testing.T) {
	k4 := &TupleKey4{
		DestAddr:   types.IPv4{10, 0, 0, 1},
		SourceAddr: types.IPv4{192, 168, 1, 2},
		DestPort:   80,
		SourcePort: 12345,
		NextHeader: u8proto.TCP,
		Flags:      TUPLE_F_IN,
	}
	var sb strings.Builder
	assert.True(t, k4.Dump(&sb, false))
	assert.Equal(t, "TCP IN 10.0.0.1 12345:80 ", sb.String())

	sb.Reset()
	k4g := &TupleKey4Global{TupleKey4: *k4}
	assert.True(t, k4g.Dump(&sb, false))
	assert.Equal(t, "TCP IN 192.168.1.2:12345 -> 10.0.0.1:80 ", sb.String())

	k6 := &TupleKey6{
		DestAddr:   types.IPv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		SourceAddr: types.IPv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		DestPort:   443,
		SourcePort: 54321,
		NextHeader: u8proto.TCP,
		Flags:      TUPLE_F_OUT,
	}
	sb.Reset()
	assert.True(t, k6.Dump(&sb, false))
	assert.Equal(t, "TCP OUT 2001:db8::1 443:54321 ", sb.String())

	sb.Reset()
	k6g := &TupleKey6Global{TupleKey6: *k6}
	assert.True(t, k6g.Dump(&sb, false))
	assert.Equal(t, "TCP OUT [2001:db8::2]:54321 -> [2001:db8::1]:443 ", sb.String())
}

func BenchmarkTupleKey4_String(b *testing.B) {
	k := &TupleKey4{
		DestAddr:   types.IPv4{10, 0, 0, 1},
		SourceAddr: types.IPv4{192, 168, 1, 2},
		DestPort:   80,
		SourcePort: 12345,
		NextHeader: u8proto.TCP,
		Flags:      TUPLE_F_IN,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k.String()
	}
}

func BenchmarkTupleKey4_Dump(b *testing.B) {
	k := &TupleKey4{
		DestAddr:   types.IPv4{10, 0, 0, 1},
		SourceAddr: types.IPv4{192, 168, 1, 2},
		DestPort:   80,
		SourcePort: 12345,
		NextHeader: u8proto.TCP,
		Flags:      TUPLE_F_IN,
	}
	var sb strings.Builder
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		sb.Reset()
		_ = k.Dump(&sb, false)
	}
}

func BenchmarkTupleKey4Global_String(b *testing.B) {
	k := &TupleKey4Global{
		TupleKey4: TupleKey4{
			DestAddr:   types.IPv4{10, 0, 0, 1},
			SourceAddr: types.IPv4{192, 168, 1, 2},
			DestPort:   80,
			SourcePort: 12345,
			NextHeader: u8proto.TCP,
			Flags:      TUPLE_F_IN,
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k.String()
	}
}

func BenchmarkTupleKey4Global_Dump(b *testing.B) {
	k := &TupleKey4Global{
		TupleKey4: TupleKey4{
			DestAddr:   types.IPv4{10, 0, 0, 1},
			SourceAddr: types.IPv4{192, 168, 1, 2},
			DestPort:   80,
			SourcePort: 12345,
			NextHeader: u8proto.TCP,
			Flags:      TUPLE_F_IN,
		},
	}
	var sb strings.Builder
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		sb.Reset()
		_ = k.Dump(&sb, false)
	}
}

func BenchmarkTupleKey6_String(b *testing.B) {
	k := &TupleKey6{
		DestAddr:   types.IPv6{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		SourceAddr: types.IPv6{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		DestPort:   443,
		SourcePort: 54321,
		NextHeader: u8proto.TCP,
		Flags:      TUPLE_F_OUT,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k.String()
	}
}

func BenchmarkTupleKey6_Dump(b *testing.B) {
	k := &TupleKey6{
		DestAddr:   types.IPv6{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		SourceAddr: types.IPv6{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		DestPort:   443,
		SourcePort: 54321,
		NextHeader: u8proto.TCP,
		Flags:      TUPLE_F_OUT,
	}
	var sb strings.Builder
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		sb.Reset()
		_ = k.Dump(&sb, false)
	}
}

func BenchmarkTupleKey6Global_String(b *testing.B) {
	k := &TupleKey6Global{
		TupleKey6: TupleKey6{
			DestAddr:   types.IPv6{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			SourceAddr: types.IPv6{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
			DestPort:   443,
			SourcePort: 54321,
			NextHeader: u8proto.TCP,
			Flags:      TUPLE_F_OUT,
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k.String()
	}
}

func BenchmarkTupleKey6Global_Dump(b *testing.B) {
	k := &TupleKey6Global{
		TupleKey6: TupleKey6{
			DestAddr:   types.IPv6{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			SourceAddr: types.IPv6{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
			DestPort:   443,
			SourcePort: 54321,
			NextHeader: u8proto.TCP,
			Flags:      TUPLE_F_OUT,
		},
	}
	var sb strings.Builder
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		sb.Reset()
		_ = k.Dump(&sb, false)
	}
}
