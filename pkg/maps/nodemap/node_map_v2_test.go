// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodemap

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/bpf"
)

func TestNodeKey_NewAndString(t *testing.T) {
	ip4 := netip.MustParseAddr("10.0.0.1")
	k4 := newNodeKey(ip4)
	assert.Equal(t, uint8(bpf.EndpointKeyIPv4), k4.Family)
	assert.Equal(t, "10.0.0.1", k4.String())

	ip6 := netip.MustParseAddr("fd00::1")
	k6 := newNodeKey(ip6)
	assert.Equal(t, uint8(bpf.EndpointKeyIPv6), k6.Family)
	assert.Equal(t, "fd00::1", k6.String())
}

func BenchmarkNewNodeKey_IPv4(b *testing.B) {
	ip := netip.MustParseAddr("10.0.0.1")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = newNodeKey(ip)
	}
}

func BenchmarkNewNodeKey_IPv6(b *testing.B) {
	ip := netip.MustParseAddr("fd00::1")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = newNodeKey(ip)
	}
}
