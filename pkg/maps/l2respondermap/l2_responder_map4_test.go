// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2respondermap

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestL2Responder_Strings(t *testing.T) {
	k := newL2ResponderKey(netip.MustParseAddr("10.0.0.1"), 42)
	assert.Equal(t, "ip=10.0.0.1, ifIndex=42", k.String())

	s := L2ResponderStats{ResponsesSent: 12345}
	assert.Equal(t, "responses_sent=12345", s.String())
}

func BenchmarkL2ResponderKey_String(b *testing.B) {
	k := newL2ResponderKey(netip.MustParseAddr("10.0.0.1"), 42)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k.String()
	}
}

func BenchmarkL2ResponderStats_String(b *testing.B) {
	s := L2ResponderStats{ResponsesSent: 12345}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = s.String()
	}
}
