// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/types"
)

func TestSRv6_Strings(t *testing.T) {
	pk4 := &PolicyKey4{
		PrefixLen: policyStaticPrefixBits + 24,
		VRFID:     10,
		DestCIDR:  types.IPv4(netip.MustParseAddr("10.0.0.0").As4()),
	}
	assert.Equal(t, "vrfid=10, destCIDR=10.0.0.0/24", pk4.String())

	pk6 := &PolicyKey6{
		PrefixLen: policyStaticPrefixBits + 64,
		VRFID:     20,
		DestCIDR:  types.IPv6(netip.MustParseAddr("fd00::").As16()),
	}
	assert.Equal(t, "vrfid=20, destCIDR=fd00::/64", pk6.String())

	pv := &PolicyValue{
		SID: types.IPv6(netip.MustParseAddr("fd00::1").As16()),
	}
	assert.Equal(t, "sid=fd00::1", pv.String())

	sk := &SIDKey{
		SID: types.IPv6(netip.MustParseAddr("fd00::1").As16()),
	}
	assert.Equal(t, "sid=fd00::1", sk.String())

	sv := &SIDValue{VRFID: 30}
	assert.Equal(t, "vrfid=30", sv.String())

	vk4 := &VRFKey4{
		PrefixLen: vrf4StaticPrefixBits + 24,
		SourceIP:  types.IPv4(netip.MustParseAddr("10.1.0.1").As4()),
		DestCIDR:  types.IPv4(netip.MustParseAddr("10.2.0.0").As4()),
	}
	assert.Equal(t, "srcip=10.1.0.1, destCIDR=10.2.0.0/24", vk4.String())

	vk6 := &VRFKey6{
		PrefixLen: vrf6StaticPrefixBits + 64,
		SourceIP:  types.IPv6(netip.MustParseAddr("fd00::1").As16()),
		DestCIDR:  types.IPv6(netip.MustParseAddr("fd00::2:0").As16()),
	}
	assert.Equal(t, "srcip=fd00::1, destCIDR=fd00::2:0/64", vk6.String())

	vv := &VRFValue{ID: 40}
	assert.Equal(t, "vrfid=40", vv.String())
}

func BenchmarkPolicyKey4_String(b *testing.B) {
	pk4 := &PolicyKey4{
		PrefixLen: policyStaticPrefixBits + 24,
		VRFID:     10,
		DestCIDR:  types.IPv4(netip.MustParseAddr("10.0.0.0").As4()),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = pk4.String()
	}
}

func BenchmarkPolicyKey6_String(b *testing.B) {
	pk6 := &PolicyKey6{
		PrefixLen: policyStaticPrefixBits + 64,
		VRFID:     20,
		DestCIDR:  types.IPv6(netip.MustParseAddr("fd00::").As16()),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = pk6.String()
	}
}
