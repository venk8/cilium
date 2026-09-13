// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2v6respondermap

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestL2V6Responder_Strings(t *testing.T) {
	k := newL2V6ResponderKey(netip.MustParseAddr("fd00::1"), 42)
	assert.Equal(t, "ip=fd00::1, ifIndex=42", k.String())
}

func BenchmarkL2V6ResponderKey_String(b *testing.B) {
	k := newL2V6ResponderKey(netip.MustParseAddr("fd00::1"), 42)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k.String()
	}
}
