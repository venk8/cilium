// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProxyID(t *testing.T) {
	id := ProxyID(123, true, "TCP", uint16(8080), "")
	require.Equal(t, "123:ingress:TCP:8080:", id)
	endpointID, ingress, protocol, port, listener, err := ParseProxyID(id)
	require.Equal(t, uint16(123), endpointID)
	require.True(t, ingress)
	require.Equal(t, "TCP", protocol)
	require.Equal(t, uint16(8080), port)
	require.Empty(t, listener)
	require.NoError(t, err)

	id = ProxyID(321, false, "TCP", uint16(80), "myListener")
	require.Equal(t, "321:egress:TCP:80:myListener", id)
	endpointID, ingress, protocol, port, listener, err = ParseProxyID(id)
	require.Equal(t, uint16(321), endpointID)
	require.False(t, ingress)
	require.Equal(t, "TCP", protocol)
	require.Equal(t, uint16(80), port)
	require.Equal(t, "myListener", listener)
	require.NoError(t, err)
}

func TestProxyStatsKey(t *testing.T) {
	key := ProxyStatsKey(true, "TCP", 80, 8080)
	require.Equal(t, "ingress:TCP:80:8080", key)

	key = ProxyStatsKey(false, "UDP", 53, 5353)
	require.Equal(t, "egress:UDP:53:5353", key)
}

func TestParseProxyID_Errors(t *testing.T) {
	_, _, _, _, _, err := ParseProxyID("123:ingress:TCP:8080")
	require.Error(t, err)

	_, _, _, _, _, err = ParseProxyID("123:ingress:TCP:8080:listener:extra")
	require.Error(t, err)

	_, _, _, _, _, err = ParseProxyID("abc:ingress:TCP:8080:")
	require.Error(t, err)

	_, _, _, _, _, err = ParseProxyID("70000:ingress:TCP:8080:")
	require.Error(t, err)

	_, _, _, _, _, err = ParseProxyID("123:ingress:TCP:xyz:")
	require.Error(t, err)

	_, _, _, _, _, err = ParseProxyID("123:ingress:TCP:70000:")
	require.Error(t, err)
}

func BenchmarkProxyID(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = ProxyID(12345, true, "TCP", 8080, "envoy-listener")
	}
}

func BenchmarkProxyStatsKey(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = ProxyStatsKey(true, "TCP", 8080, 18080)
	}
}

func BenchmarkParseProxyID(b *testing.B) {
	id := ProxyID(12345, true, "TCP", 8080, "envoy-listener")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _, _, _, _, _ = ParseProxyID(id)
	}
}
