// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/types"
)

func TestVtepEndpointInfoString(t *testing.T) {
	m, err := mac.ParseMAC("00:11:22:33:44:55")
	require.NoError(t, err)

	info := VtepEndpointInfo{
		VtepMAC:        m,
		TunnelEndpoint: types.IPv4{10, 0, 1, 2},
	}

	require.Equal(t, "vtepmac=00:11:22:33:44:55 tunnelendpoint=10.0.1.2", info.String())
}

func BenchmarkVtepEndpointInfoString(b *testing.B) {
	m, _ := mac.ParseMAC("00:11:22:33:44:55")
	info := VtepEndpointInfo{
		VtepMAC:        m,
		TunnelEndpoint: types.IPv4{10, 0, 1, 2},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = info.String()
	}
}

