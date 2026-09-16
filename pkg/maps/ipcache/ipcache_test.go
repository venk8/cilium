// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"testing"
)

func TestRemoteEndpointInfoFlagsStringReturnsCorrectValue(t *testing.T) {
	type stringTest struct {
		name string
		in   RemoteEndpointInfoFlags
		out  string
	}

	tests := []stringTest{
		{
			name: "no flags",
			in:   0,
			out:  "<none>",
		},
		{
			name: "FlagSkipTunnel",
			in:   FlagSkipTunnel,
			out:  "skiptunnel",
		},
		{
			name: "Multiple flags",
			in:   FlagSkipTunnel | FlagIPv6TunnelEndpoint,
			out:  "skiptunnel,ipv6tunnel",
		},
	}

	for _, test := range tests {
		if s := test.in.String(); s != test.out {
			t.Errorf(
				"Expected '%s' for string representation of %s, instead got '%s'",
				test.out, test.name, s,
			)
		}
	}
}

func BenchmarkRemoteEndpointInfoFlags_String(b *testing.B) {
	flags := FlagSkipTunnel | FlagIPv6TunnelEndpoint
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = flags.String()
	}
}

func BenchmarkRemoteEndpointInfo_String(b *testing.B) {
	info := &RemoteEndpointInfo{
		SecurityIdentity: 12345,
		Key:              3,
		Flags:            FlagSkipTunnel | FlagHasTunnelEndpoint,
	}
	info.TunnelEndpoint[0] = 10
	info.TunnelEndpoint[1] = 0
	info.TunnelEndpoint[2] = 1
	info.TunnelEndpoint[3] = 2
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = info.String()
	}
}

func BenchmarkKey_String(b *testing.B) {
	key := Key{
		Prefixlen: 32 + staticPrefixBits,
		Family:    1, // EndpointKeyIPv4
		ClusterID: 5,
	}
	key.IP[0] = 192
	key.IP[1] = 168
	key.IP[2] = 1
	key.IP[3] = 10
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = key.String()
	}
}

