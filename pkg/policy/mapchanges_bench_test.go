// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/policy/types"
)

func BenchmarkMapChanges_EmptyConsume(b *testing.B) {
	logger := hivetest.Logger(b)
	mc := MapChanges{logger: logger}
	epPolicy := &EndpointPolicy{
		policyMapState: emptyMapState(logger),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		mc.consumeMapChanges(epPolicy, 0)
	}
}

func BenchmarkMapChanges_AccumulateAndConsume(b *testing.B) {
	logger := hivetest.Logger(b)
	k := KeyForDirection(trafficdirection.Egress).WithPortProto(6, 80)
	v := newAllowEntryWithLabels(nil)
	nids := make(identity.NumericIdentitySlice, 100)
	for i := range nids {
		nids[i] = identity.NumericIdentity(1000 + i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		epPolicy := &EndpointPolicy{
			policyMapState: emptyMapState(logger),
		}
		mc := MapChanges{logger: logger}
		mc.AccumulateMapChanges(0, 0, nids, nil, k, v)
		mc.SyncMapChanges(types.MockSelectorSnapshot())
		mc.consumeMapChanges(epPolicy, 0)
	}
}
