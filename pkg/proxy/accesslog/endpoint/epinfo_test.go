// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	sourceKnown "github.com/cilium/cilium/pkg/source"
)

type mockEndpointLookup struct {
	endpointmanager.EndpointsLookup
}

func (m *mockEndpointLookup) LookupIP(ip netip.Addr) *endpoint.Endpoint {
	return nil
}

type mockIdentityAllocator struct {
	cache.IdentityAllocator
}

func (m *mockIdentityAllocator) LookupIdentityByID(ctx context.Context, id identity.NumericIdentity) *identity.Identity {
	return nil
}

func TestFillEndpointInfo(t *testing.T) {
	ctx := context.Background()
	logger := hivetest.Logger(t)
	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context: ctx,
		Logger:  logger,
	})
	t.Cleanup(func() { ipc.Shutdown() })

	testIP := netip.MustParseAddr("10.0.1.20")
	testSecID := identity.NumericIdentity(4242)

	ipc.Upsert(testIP.String(), nil, 0, nil, ipcache.Identity{
		ID:     testSecID,
		Source: sourceKnown.Local,
	})

	registry := NewEndpointInfoRegistry(ipc, &mockEndpointLookup{}, &mockIdentityAllocator{})

	info := accesslog.EndpointInfo{}
	registry.FillEndpointInfo(ctx, &info, testIP)

	require.Equal(t, "10.0.1.20", info.IPv4)
	require.Equal(t, uint64(testSecID), info.Identity)
}

func BenchmarkFillEndpointInfo(b *testing.B) {
	ctx := context.Background()
	logger := hivetest.Logger(b)
	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context: ctx,
		Logger:  logger,
	})
	b.Cleanup(func() { ipc.Shutdown() })

	testIP := netip.MustParseAddr("10.0.1.20")
	testSecID := identity.NumericIdentity(4242)

	ipc.Upsert(testIP.String(), nil, 0, nil, ipcache.Identity{
		ID:     testSecID,
		Source: sourceKnown.Local,
	})

	registry := NewEndpointInfoRegistry(ipc, &mockEndpointLookup{}, &mockIdentityAllocator{})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		info := accesslog.EndpointInfo{}
		registry.FillEndpointInfo(ctx, &info, testIP)
	}
}
