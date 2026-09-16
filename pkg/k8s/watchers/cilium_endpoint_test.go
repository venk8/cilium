// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/source"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
)

type benchPolicyManager struct {
	reasons []string
}

func (b *benchPolicyManager) TriggerPolicyUpdates(reason string) {
	b.reasons = append(b.reasons, reason)
}

type benchIPCacheManager struct {
	upserts    int
	deletes    int
	deletedIPs []string
}

func (b *benchIPCacheManager) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (bool, error) {
	b.upserts++
	return false, nil
}

func (b *benchIPCacheManager) LookupByIP(IP string) (ipcache.Identity, bool) {
	return ipcache.Identity{}, false
}

func (b *benchIPCacheManager) UpsertMetadata(prefix cmtypes.PrefixCluster, src source.Source, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata) {
}

func (b *benchIPCacheManager) RemoveLabelsExcluded(lbls labels.Labels, toExclude map[cmtypes.PrefixCluster]struct{}, resource ipcacheTypes.ResourceID) {
}

func (b *benchIPCacheManager) DeleteOnMetadataMatch(IP string, source source.Source, namespace, name, uid string) bool {
	b.deletes++
	if len(b.deletedIPs) < 16 {
		b.deletedIPs = append(b.deletedIPs, IP)
	}
	return false
}

func TestK8sCiliumEndpointsWatcher_EndpointUpdated_NoEmptyIPDelete(t *testing.T) {
	ipc := &benchIPCacheManager{}
	k := &K8sCiliumEndpointsWatcher{
		logger:         hivetest.Logger(t),
		policyManager:  &benchPolicyManager{},
		ipcache:        ipc,
		localNodeStore: node.NewTestLocalNodeStore(node.LocalNode{}),
		wgConfig:       fakewireguard.Config{},
		ipsecConfig:    fakeipsec.Config{},
	}

	oldEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "test-cep",
			Namespace: "default",
		},
		Networking: &v2.EndpointNetworking{
			NodeIP: "192.168.1.1",
			Addressing: v2.AddressPairList{
				{IPV4: "10.244.0.1"},
			},
		},
	}
	newEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "test-cep",
			Namespace: "default",
		},
		Networking: &v2.EndpointNetworking{
			NodeIP: "192.168.1.1",
			Addressing: v2.AddressPairList{
				{IPV4: "10.244.0.2"},
			},
		},
	}

	k.endpointUpdated(oldEP, newEP)

	if ipc.deletes != 1 {
		t.Fatalf("expected exactly 1 delete, got %d", ipc.deletes)
	}
	if len(ipc.deletedIPs) != 1 || ipc.deletedIPs[0] != "10.244.0.1" {
		t.Fatalf("expected delete for 10.244.0.1, got %v", ipc.deletedIPs)
	}
}

func BenchmarkK8sCiliumEndpointsWatcher_EndpointUpdated(b *testing.B) {
	ipc := &benchIPCacheManager{}
	k := &K8sCiliumEndpointsWatcher{
		logger:         hivetest.Logger(b),
		policyManager:  &benchPolicyManager{},
		ipcache:        ipc,
		localNodeStore: node.NewTestLocalNodeStore(node.LocalNode{}),
		wgConfig:       fakewireguard.Config{},
		ipsecConfig:    fakeipsec.Config{},
	}
	oldEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "test-cep",
			Namespace: "default",
		},
		Networking: &v2.EndpointNetworking{
			NodeIP: "192.168.1.1",
			Addressing: v2.AddressPairList{
				{IPV4: "10.244.0.1"},
			},
		},
	}
	newEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "test-cep",
			Namespace: "default",
		},
		Networking: &v2.EndpointNetworking{
			NodeIP: "192.168.1.1",
			Addressing: v2.AddressPairList{
				{IPV4: "10.244.0.2"},
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.endpointUpdated(oldEP, newEP)
	}
}

func BenchmarkK8sCiliumEndpointsWatcher_EndpointUpdated_NoIPChange(b *testing.B) {
	ipc := &benchIPCacheManager{}
	k := &K8sCiliumEndpointsWatcher{
		logger:         hivetest.Logger(b),
		policyManager:  &benchPolicyManager{},
		ipcache:        ipc,
		localNodeStore: node.NewTestLocalNodeStore(node.LocalNode{}),
		wgConfig:       fakewireguard.Config{},
		ipsecConfig:    fakeipsec.Config{},
	}
	oldEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "test-cep",
			Namespace: "default",
		},
		Networking: &v2.EndpointNetworking{
			NodeIP: "192.168.1.1",
			Addressing: v2.AddressPairList{
				{IPV4: "10.244.0.1"},
			},
		},
	}
	newEP := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "test-cep",
			Namespace: "default",
		},
		Networking: &v2.EndpointNetworking{
			NodeIP: "192.168.1.1",
			Addressing: v2.AddressPairList{
				{IPV4: "10.244.0.1"},
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.endpointUpdated(oldEP, newEP)
	}
}
