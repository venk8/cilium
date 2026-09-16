// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/hive/hivetest"
)

func BenchmarkInjectLabels(b *testing.B) {
	s := setupIPCacheTestSuite(b)
	ipc := s.IPIdentityCache

	addr := netip.MustParseAddr("1.0.0.0")
	lbls := labels.NewLabelsFromSortedList(labels.LabelSourceCIDRGroup + ":foo=bar")

	prefixes := make([]cmtypes.PrefixCluster, 0, b.N)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; b.Loop(); i++ {
		pfx := cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(addr, 30))
		for range 4 {
			addr = addr.Next()
		}
		prefixes = append(prefixes, ipc.metadata.upsertLocked(pfx, source.Kubernetes, "cidr-policy", lbls)...)
		if i%1000 == 0 {
			b.Log(i)
		}
	}
	b.Logf("%d", len(prefixes))
	b.Log(addr.String())
	_, err := ipc.doInjectLabels(b.Context(), prefixes)
	if err != nil {
		b.Fatal(err)
	}

	b.StopTimer()

	// sanity checks
	require.Len(b, ipc.ipToIdentityCache, len(prefixes))
}

func BenchmarkLookupSecIDByIP(b *testing.B) {
	s := setupIPCacheTestSuite(b)
	ipc := s.IPIdentityCache

	_, _ = ipc.Upsert("10.0.0.0/8", nil, 0, nil, Identity{
		ID:     identity.NumericIdentity(100),
		Source: source.Kubernetes,
	})

	lookupIP := netip.MustParseAddr("10.1.2.3")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ipc.LookupSecIDByIP(lookupIP)
	}
}

func BenchmarkLookupByPrefix(b *testing.B) {
	s := setupIPCacheTestSuite(b)
	ipc := s.IPIdentityCache

	_, _ = ipc.Upsert("10.0.0.0/8", nil, 0, nil, Identity{
		ID:     identity.NumericIdentity(100),
		Source: source.Kubernetes,
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ipc.LookupByPrefix("10.0.0.0/8")
	}
}

func BenchmarkLookupByPrefixSingleIP(b *testing.B) {
	s := setupIPCacheTestSuite(b)
	ipc := s.IPIdentityCache

	_, _ = ipc.Upsert("10.0.0.1", nil, 0, nil, Identity{
		ID:     identity.NumericIdentity(100),
		Source: source.Kubernetes,
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ipc.LookupByPrefix("10.0.0.1/32")
	}
}

func BenchmarkPrefixInfoFlattenSingle(b *testing.B) {
	logger := hivetest.Logger(b)
	pi := newPrefixInfo()
	resID := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindCNP, "default", "policy")
	pi.byResource[resID] = &resourceInfo{
		source: source.Kubernetes,
		labels: labels.NewLabelsFromSortedList("k8s:app=foo,k8s:env=prod"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pi.flatten(logger)
	}
}

func BenchmarkMergeLabels(b *testing.B) {
	logger := hivetest.Logger(b)
	m := newMetadata(logger)

	parentPfx := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.0.0.0/8"))
	childPfx := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.1.2.0/24"))
	parentLbls := labels.GetCIDRLabels(parentPfx.AsPrefix())
	childLbls := labels.GetCIDRLabels(childPfx.AsPrefix())

	m.upsertLocked(parentPfx, source.Kubernetes, "cidr-policy", parentLbls)
	m.upsertLocked(childPfx, source.Kubernetes, "cidr-policy", childLbls)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		target := labels.GetCIDRLabels(childPfx.AsPrefix())
		m.mergeLabels(target, childPfx)
	}
}


