// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	envoyAPI "github.com/cilium/proxy/go/cilium/api"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
)

func TestHandleIPUpsert(t *testing.T) {
	cache := newNPHDSCache(hivetest.Logger(t), nil)

	msg := cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	require.Nil(t, msg)

	err := cache.handleIPUpsert(nil, "123", "1.2.3.0/32", 123)
	require.NoError(t, err)

	msg = cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	require.NotNil(t, msg)
	npHost := msg.(*envoyAPI.NetworkPolicyHosts)
	require.NotNil(t, npHost)
	require.Equal(t, uint64(123), npHost.Policy)
	require.Len(t, npHost.HostAddresses, 1)
	require.Equal(t, "1.2.3.0/32", npHost.HostAddresses[0])

	// Another address
	err = cache.handleIPUpsert(npHost, "123", "::1/128", 123)
	require.NoError(t, err)

	msg = cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	require.NotNil(t, msg)
	npHost = msg.(*envoyAPI.NetworkPolicyHosts)
	require.NotNil(t, npHost)
	require.Equal(t, uint64(123), npHost.Policy)
	require.Len(t, npHost.HostAddresses, 2)
	require.Equal(t, "1.2.3.0/32", npHost.HostAddresses[0])
	require.Equal(t, "::1/128", npHost.HostAddresses[1])

	// Check that duplicates are not added, and not erroring out
	err = cache.handleIPUpsert(npHost, "123", "1.2.3.0/32", 123)
	require.NoError(t, err)

	msg = cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	require.NotNil(t, msg)
	npHost = msg.(*envoyAPI.NetworkPolicyHosts)
	require.NotNil(t, npHost)
	require.Equal(t, uint64(123), npHost.Policy)
	require.Len(t, npHost.HostAddresses, 2)
	require.Equal(t, "1.2.3.0/32", npHost.HostAddresses[0])
	require.Equal(t, "::1/128", npHost.HostAddresses[1])
}

func BenchmarkNPHDSCache_HandleIPUpsert(b *testing.B) {
	cache := newNPHDSCache(hivetest.Logger(b), nil)
	npHost := &envoyAPI.NetworkPolicyHosts{
		Policy: 123,
		HostAddresses: []string{
			"10.0.0.1/32",
			"10.0.0.2/32",
			"10.0.0.3/32",
			"10.0.0.4/32",
			"10.0.0.5/32",
		},
	}
	cache.Upsert(NetworkPolicyHostsTypeURL, "123", npHost)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = cache.handleIPUpsert(npHost, "123", "10.0.0.3/32", 123)
	}
}

func BenchmarkNPHDSCache_OnIPIdentityCacheChange(b *testing.B) {
	cache := newNPHDSCache(hivetest.Logger(b), nil)
	cidrCluster := cmtypes.MustParsePrefixCluster("10.0.0.1/32")
	id := ipcache.Identity{ID: 123}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		cache.OnIPIdentityCacheChange(ipcache.Upsert, cidrCluster, nil, nil, nil, id, 0, nil, 0)
	}
}


