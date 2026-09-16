// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type fakeNodeManager struct {
	updatedCount atomic.Int64
	deletedCount atomic.Int64
	syncCount    atomic.Int64
}

func (f *fakeNodeManager) NodeUpdated(n nodeTypes.Node) {
	f.updatedCount.Add(1)
}

func (f *fakeNodeManager) NodeDeleted(n nodeTypes.Node) {
	f.deletedCount.Add(1)
}

func (f *fakeNodeManager) NodeSync() {
	f.syncCount.Add(1)
}

func createTestCiliumNode(name string, statusIP string) *cilium_v2.CiliumNode {
	used := make(ipamTypes.AllocationMap, 100)
	for i := 0; i < 100; i++ {
		used[fmt.Sprintf("10.244.0.%d", i)] = ipamTypes.AllocationIP{Owner: fmt.Sprintf("default/pod-%d", i)}
	}
	used[statusIP] = ipamTypes.AllocationIP{Owner: "default/pod-active"}

	return &cilium_v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"topology.kubernetes.io/zone":      "us-west1-a",
				"node.kubernetes.io/instance-type": "n2-standard-4",
			},
			Annotations: map[string]string{
				"network.cilium.io/wg-pub-key": "fake-wg-pub-key-12345",
			},
		},
		Spec: cilium_v2.NodeSpec{
			BootID: "boot-id-123",
			Addresses: []cilium_v2.NodeAddress{
				{Type: addressing.NodeInternalIP, IP: "10.0.0.1"},
				{Type: addressing.NodeCiliumInternalIP, IP: "10.244.0.1"},
			},
			HealthAddressing: cilium_v2.HealthAddressingSpec{
				IPv4: "10.244.0.2",
			},
		},
		Status: cilium_v2.NodeStatus{
			IPAM: ipamTypes.IPAMStatus{
				Used: used,
			},
		},
	}
}

func TestCiliumNodeWatcher_StatusOnlyUpdate(t *testing.T) {
	fakeMgr := &fakeNodeManager{}
	watcher := &K8sCiliumNodeWatcher{
		logger:      slog.Default(),
		nodeManager: fakeMgr,
		clusterInfo: cmtypes.ClusterInfo{ID: 1, Name: "default"},
	}

	oldNode := createTestCiliumNode("remote-node-1", "10.244.0.12")
	newNode := createTestCiliumNode("remote-node-1", "10.244.0.99") // only Status IPAM changed

	needUpdate := watcher.onCiliumNodeUpdate(oldNode, newNode)
	assert.False(t, needUpdate, "Status-only update should not require node update")
	assert.Equal(t, int64(0), fakeMgr.updatedCount.Load(), "NodeUpdated should not be called for status-only update")
}

func TestCiliumNodeWatcher_SpecChanged(t *testing.T) {
	fakeMgr := &fakeNodeManager{}
	watcher := &K8sCiliumNodeWatcher{
		logger:      slog.Default(),
		nodeManager: fakeMgr,
		clusterInfo: cmtypes.ClusterInfo{ID: 1, Name: "default"},
	}

	oldNode := createTestCiliumNode("remote-node-1", "10.244.0.12")
	newNode := createTestCiliumNode("remote-node-1", "10.244.0.12")
	newNode.Spec.Addresses = append(newNode.Spec.Addresses, cilium_v2.NodeAddress{
		Type: addressing.NodeExternalIP,
		IP:   "198.51.100.1",
	})

	needUpdate := watcher.onCiliumNodeUpdate(oldNode, newNode)
	assert.True(t, needUpdate, "Spec change must require node update")
	assert.Equal(t, int64(1), fakeMgr.updatedCount.Load(), "NodeUpdated should be called for spec update")
}

func TestCiliumNodeWatcher_LabelsChanged(t *testing.T) {
	fakeMgr := &fakeNodeManager{}
	watcher := &K8sCiliumNodeWatcher{
		logger:      slog.Default(),
		nodeManager: fakeMgr,
		clusterInfo: cmtypes.ClusterInfo{ID: 1, Name: "default"},
	}

	oldNode := createTestCiliumNode("remote-node-1", "10.244.0.12")
	newNode := createTestCiliumNode("remote-node-1", "10.244.0.12")
	newNode.Labels["topology.kubernetes.io/zone"] = "us-west1-b"

	needUpdate := watcher.onCiliumNodeUpdate(oldNode, newNode)
	assert.True(t, needUpdate, "Label change must require node update")
	assert.Equal(t, int64(1), fakeMgr.updatedCount.Load(), "NodeUpdated should be called for label update")
}

func TestCiliumNodeWatcher_AnnotationsChanged(t *testing.T) {
	fakeMgr := &fakeNodeManager{}
	watcher := &K8sCiliumNodeWatcher{
		logger:      slog.Default(),
		nodeManager: fakeMgr,
		clusterInfo: cmtypes.ClusterInfo{ID: 1, Name: "default"},
	}

	oldNode := createTestCiliumNode("remote-node-1", "10.244.0.12")
	newNode := createTestCiliumNode("remote-node-1", "10.244.0.12")
	newNode.Annotations["network.cilium.io/wg-pub-key"] = "new-rotated-wg-key-67890"

	needUpdate := watcher.onCiliumNodeUpdate(oldNode, newNode)
	assert.True(t, needUpdate, "WireGuard key annotation rotation must require node update")
	assert.Equal(t, int64(1), fakeMgr.updatedCount.Load(), "NodeUpdated should be called for annotation update")
}

func TestCiliumNodeWatcher_LocalNodeIgnored(t *testing.T) {
	nodeTypes.SetName("local-node")
	defer nodeTypes.SetName("")

	fakeMgr := &fakeNodeManager{}
	watcher := &K8sCiliumNodeWatcher{
		logger:      slog.Default(),
		nodeManager: fakeMgr,
		clusterInfo: cmtypes.ClusterInfo{ID: 1, Name: "default"},
	}

	localNode := createTestCiliumNode("local-node", "10.244.0.12")
	inserted := watcher.onCiliumNodeInsert(localNode)
	assert.False(t, inserted, "Local node insert must be ignored")
	assert.Equal(t, int64(0), fakeMgr.updatedCount.Load())
}

func TestCloneForNodeWatcher(t *testing.T) {
	node := createTestCiliumNode("remote-node-1", "10.244.0.12")
	cloned := cloneForNodeWatcher(node)
	require.NotNil(t, cloned)
	assert.Equal(t, node.Name, cloned.Name)
	assert.True(t, node.Spec.DeepEqual(&cloned.Spec))
	assert.Equal(t, node.Labels, cloned.Labels)
	assert.Equal(t, node.Annotations, cloned.Annotations)
	assert.Empty(t, cloned.Status.IPAM.Used, "Status must be empty in watcher cached clone")
}

func BenchmarkOnCiliumNodeUpdate_StatusOnly(b *testing.B) {
	fakeMgr := &fakeNodeManager{}
	watcher := &K8sCiliumNodeWatcher{
		logger:      slog.Default(),
		nodeManager: fakeMgr,
		clusterInfo: cmtypes.ClusterInfo{ID: 1, Name: "default"},
	}

	oldNode := createTestCiliumNode("remote-node-1", "10.244.0.12")
	newNode := createTestCiliumNode("remote-node-1", "10.244.0.99")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		watcher.onCiliumNodeUpdate(oldNode, newNode)
	}
}

func BenchmarkOnCiliumNodeUpdate_SpecChanged(b *testing.B) {
	fakeMgr := &fakeNodeManager{}
	watcher := &K8sCiliumNodeWatcher{
		logger:      slog.Default(),
		nodeManager: fakeMgr,
		clusterInfo: cmtypes.ClusterInfo{ID: 1, Name: "default"},
	}

	oldNode := createTestCiliumNode("remote-node-1", "10.244.0.12")
	newNode := createTestCiliumNode("remote-node-1", "10.244.0.12")
	newNode.Spec.BootID = "boot-id-456"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		watcher.onCiliumNodeUpdate(oldNode, newNode)
	}
}

func BenchmarkCloneForNodeWatcher_vs_DeepCopy(b *testing.B) {
	node := createTestCiliumNode("remote-node-1", "10.244.0.12")

	b.Run("Standard_DeepCopy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = node.DeepCopy()
		}
	})

	b.Run("CloneForNodeWatcher", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = cloneForNodeWatcher(node)
		}
	})
}
