// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package addressing

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockStringAddress struct {
	addrType AddressType
	ip       string
}

func (m mockStringAddress) AddrType() AddressType {
	return m.addrType
}

func (m mockStringAddress) ToString() string {
	return m.ip
}

func (m mockStringAddress) GetIP() net.IP {
	return net.ParseIP(m.ip)
}

type mockDirectIPAddress struct {
	addrType AddressType
	ip       net.IP
}

func (m mockDirectIPAddress) AddrType() AddressType {
	return m.addrType
}

func (m mockDirectIPAddress) ToString() string {
	return m.ip.String()
}

func (m mockDirectIPAddress) GetIP() net.IP {
	return m.ip
}

func TestExtractNodeIP(t *testing.T) {
	addrs := []mockStringAddress{
		{addrType: NodeHostName, ip: "my-node.internal"},
		{addrType: NodeCiliumInternalIP, ip: "10.0.0.1"},
		{addrType: NodeExternalIP, ip: "35.200.10.1"},
		{addrType: NodeInternalIP, ip: "192.168.1.10"},
	}

	ip4 := ExtractNodeIP(addrs, false)
	require.Equal(t, net.ParseIP("192.168.1.10"), ip4)

	ip6 := ExtractNodeIP(addrs, true)
	require.Nil(t, ip6)

	directAddrs := []mockDirectIPAddress{
		{addrType: NodeHostName, ip: net.ParseIP("10.0.0.1")},
		{addrType: NodeCiliumInternalIP, ip: net.ParseIP("10.0.0.2")},
		{addrType: NodeExternalIP, ip: net.ParseIP("35.200.10.1")},
		{addrType: NodeInternalIP, ip: net.ParseIP("192.168.1.10")},
	}
	directIP4 := ExtractNodeIP(directAddrs, false)
	require.Equal(t, net.ParseIP("192.168.1.10"), directIP4)
}

func BenchmarkExtractNodeIP_Direct(b *testing.B) {
	directAddrs := []mockDirectIPAddress{
		{addrType: NodeHostName, ip: net.ParseIP("10.0.0.1")},
		{addrType: NodeCiliumInternalIP, ip: net.ParseIP("10.0.0.2")},
		{addrType: NodeExternalIP, ip: net.ParseIP("35.200.10.1")},
		{addrType: NodeInternalIP, ip: net.ParseIP("192.168.1.10")},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ExtractNodeIP(directAddrs, false)
	}
}

func BenchmarkExtractNodeIP_String(b *testing.B) {
	addrs := []mockStringAddress{
		{addrType: NodeHostName, ip: "my-node.internal"},
		{addrType: NodeCiliumInternalIP, ip: "10.0.0.1"},
		{addrType: NodeExternalIP, ip: "35.200.10.1"},
		{addrType: NodeInternalIP, ip: "192.168.1.10"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ExtractNodeIP(addrs, false)
	}
}
