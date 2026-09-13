// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

var testIPv4Address IPv4 = [4]byte{10, 0, 0, 2}

func TestAddr(t *testing.T) {
	expectedAddress := netip.MustParseAddr("10.0.0.2")
	result := testIPv4Address.Addr()

	require.Equal(t, expectedAddress, result)
}

func TestString(t *testing.T) {
	expectedStr := "10.0.0.2"
	result := testIPv4Address.String()

	require.Equal(t, expectedStr, result)
}

func BenchmarkIPv4_FromAddr(b *testing.B) {
	addr := netip.MustParseAddr("10.0.0.2")
	var v4 IPv4
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		v4.FromAddr(addr)
	}
}

func BenchmarkIPv4_IsZero(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = testIPv4Address.IsZero()
	}
}

func BenchmarkIPv4_AppendTo(b *testing.B) {
	var buf [32]byte
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = testIPv4Address.AppendTo(buf[:0])
	}
}
