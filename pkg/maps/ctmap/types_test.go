// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
)

func TestCtEntryStringAndDump(t *testing.T) {
	k := &CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: [4]byte{10, 0, 0, 1},
				DestAddr:   [4]byte{10, 0, 0, 2},
				SourcePort: 12345,
				DestPort:   80,
				NextHeader: 6,
				Flags:      TUPLE_F_IN,
			},
		},
	}
	var sb strings.Builder
	assert.True(t, k.Dump(&sb, false))
	t.Logf("Dump: %q", sb.String())

	e := &CtEntry{
		Packets:          100,
		Bytes:            1500,
		Lifetime:         300,
		Flags:            RxClosing | SeenNonSyn | NodePort,
		RevNAT:           80,
		NatPort:          1024,
		SourceSecurityID: 1234,
	}
	t.Logf("String: %q", e.StringWithTimeDiff(func(uint32) string { return "5sec" }))
}

func TestMapKey(t *testing.T) {
	for mapType := range mapTypeMax {
		assert.NotNil(t, mapType.key())
	}

	assert.Panics(t, func() { mapType(-1).key() })
	assert.Panics(t, func() { mapTypeMax.key() })
}

func TestMaxEntries(t *testing.T) {
	tests := []struct {
		name       string
		tcp, any   int
		etcp, eany int
	}{
		{
			name: "defaults",
			etcp: option.CTMapEntriesGlobalTCPDefault,
			eany: option.CTMapEntriesGlobalAnyDefault,
		},
		{
			name: "configured",
			tcp:  0x12345,
			etcp: 0x12345,
			any:  0x67890,
			eany: 0x67890,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.CTMapEntriesGlobalTCP = tt.tcp
			option.Config.CTMapEntriesGlobalAny = tt.any

			for mapType := range mapTypeMax {
				if mapType.isTCP() {
					assert.Equal(t, tt.etcp, mapType.maxEntries())
				} else {
					assert.Equal(t, tt.eany, mapType.maxEntries())
				}
			}

			assert.Panics(t, func() { mapType(-1).maxEntries() })
			assert.Panics(t, func() { mapTypeMax.maxEntries() })
		})
	}
}

func BenchmarkCtEntryFlagsString(b *testing.B) {
	e := &CtEntry{
		Flags: RxClosing | SeenNonSyn | NodePort,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = e.flagsString()
	}
}

func BenchmarkCtKey4GlobalDump(b *testing.B) {
	k := &CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: [4]byte{10, 0, 0, 1},
				DestAddr:   [4]byte{10, 0, 0, 2},
				SourcePort: 12345,
				DestPort:   80,
				NextHeader: 6,
				Flags:      TUPLE_F_IN,
			},
		},
	}
	var sb strings.Builder
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		sb.Reset()
		_ = k.Dump(&sb, false)
	}
}

func BenchmarkCtKey6GlobalDump(b *testing.B) {
	k := &CtKey6Global{
		TupleKey6Global: tuple.TupleKey6Global{
			TupleKey6: tuple.TupleKey6{
				SourceAddr: [16]byte{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
				DestAddr:   [16]byte{0x20, 0x01, 0xdb, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
				SourcePort: 12345,
				DestPort:   80,
				NextHeader: 6,
				Flags:      TUPLE_F_IN,
			},
		},
	}
	var sb strings.Builder
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		sb.Reset()
		_ = k.Dump(&sb, false)
	}
}

func BenchmarkCtEntryString(b *testing.B) {
	e := &CtEntry{
		Packets:          100,
		Bytes:            1500,
		Lifetime:         300,
		Flags:            RxClosing | SeenNonSyn | NodePort,
		RevNAT:           80,
		NatPort:          1024,
		SourceSecurityID: 1234,
	}
	toRemSecs := func(uint32) string { return "5sec" }
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = e.StringWithTimeDiff(toRemSecs)
	}
}
