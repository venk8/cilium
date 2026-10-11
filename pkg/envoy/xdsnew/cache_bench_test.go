// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"fmt"
	"log/slog"
	"maps"
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

var benchResourceVersionSink string

type benchCall struct {
	typeURL        string
	resources      map[string]cache_types.Resource
	versionContext []string
}

func buildBenchmarkEndpoint(name, podIP string, port uint32) *envoy_config_endpoint.ClusterLoadAssignment {
	return &envoy_config_endpoint.ClusterLoadAssignment{
		ClusterName: name,
		Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{
			{
				Locality: &envoy_config_core.Locality{
					Region:  "us-west",
					Zone:    "us-west-1",
					SubZone: "us-west-1a",
				},
				LbEndpoints: []*envoy_config_endpoint.LbEndpoint{
					{
						HostIdentifier: &envoy_config_endpoint.LbEndpoint_Endpoint{
							Endpoint: &envoy_config_endpoint.Endpoint{
								Address: &envoy_config_core.Address{
									Address: &envoy_config_core.Address_SocketAddress{
										SocketAddress: &envoy_config_core.SocketAddress{
											Protocol: envoy_config_core.SocketAddress_TCP,
											Address:  podIP,
											PortSpecifier: &envoy_config_core.SocketAddress_PortValue{
												PortValue: port,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func buildBenchmarkNetworkPolicy(epID uint64, podIP string, remoteIDs []uint32) *cilium.NetworkPolicy {
	return &cilium.NetworkPolicy{
		EndpointId:  epID,
		EndpointIps: []string{podIP},
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     8080,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: remoteIDs,
					},
				},
			},
			{
				Port:     8443,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: remoteIDs,
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: envoy_config_core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint32{1, 2},
					},
				},
			},
			{
				Port:     53,
				Protocol: envoy_config_core.SocketAddress_UDP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint32{1, 2, 3},
					},
				},
			},
		},
	}
}

func buildBenchmarkCluster(name string) *envoy_config_cluster.Cluster {
	return &envoy_config_cluster.Cluster{
		Name: name,
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{
			ServiceName: name,
		},
	}
}

func buildBenchmarkChurnCalls() []benchCall {
	const initialPods = 60
	const clustersCount = 30

	endpoints := make(map[string]cache_types.Resource, initialPods)
	policies := make(map[string]cache_types.Resource, initialPods)
	clusters := make(map[string]cache_types.Resource, clustersCount)

	for i := 0; i < clustersCount; i++ {
		cName := fmt.Sprintf("k8s/default/service-%d:8080", i)
		clusters[cName] = buildBenchmarkCluster(cName)
	}

	for i := 0; i < initialPods; i++ {
		podIP := fmt.Sprintf("10.244.%d.%d", (i+1)/256, (i+1)%256)
		epName := fmt.Sprintf("k8s/default/service-%d:8080", i)
		npName := fmt.Sprintf("np-%d", i)
		remoteIDs := []uint32{uint32(100 + i%10), uint32(200 + i%5), uint32(300 + (i*7)%25)}

		endpoints[epName] = buildBenchmarkEndpoint(epName, podIP, 8080)
		policies[npName] = buildBenchmarkNetworkPolicy(uint64(1000+i), podIP, remoteIDs)
	}

	type churnState struct {
		endpoints map[string]cache_types.Resource
		policies  map[string]cache_types.Resource
		clusters  map[string]cache_types.Resource
	}

	states := make([]churnState, 8)

	// Step 0: base state
	states[0] = churnState{
		endpoints: maps.Clone(endpoints),
		policies:  maps.Clone(policies),
		clusters:  maps.Clone(clusters),
	}

	// Step 1: pod 60 added
	ep60 := maps.Clone(states[0].endpoints)
	np60 := maps.Clone(states[0].policies)
	podIP60 := "10.244.0.61"
	ep60["k8s/default/service-60:8080"] = buildBenchmarkEndpoint("k8s/default/service-60:8080", podIP60, 8080)
	np60["np-60"] = buildBenchmarkNetworkPolicy(1060, podIP60, []uint32{105, 201, 310})
	states[1] = churnState{endpoints: ep60, policies: np60, clusters: states[0].clusters}

	// Step 2: pod 61 added
	ep61 := maps.Clone(states[1].endpoints)
	np61 := maps.Clone(states[1].policies)
	podIP61 := "10.244.0.62"
	ep61["k8s/default/service-61:8080"] = buildBenchmarkEndpoint("k8s/default/service-61:8080", podIP61, 8080)
	np61["np-61"] = buildBenchmarkNetworkPolicy(1061, podIP61, []uint32{106, 202, 311})
	states[2] = churnState{endpoints: ep61, policies: np61, clusters: states[0].clusters}

	// Step 3: pod 5 removed
	epDel5 := maps.Clone(states[2].endpoints)
	npDel5 := maps.Clone(states[2].policies)
	delete(epDel5, "k8s/default/service-5:8080")
	delete(npDel5, "np-5")
	states[3] = churnState{endpoints: epDel5, policies: npDel5, clusters: states[0].clusters}

	// Step 4: pod 25 network policy updated with new remote identities
	npUpdate25 := maps.Clone(states[3].policies)
	npUpdate25["np-25"] = buildBenchmarkNetworkPolicy(1025, "10.244.0.26", []uint32{100, 105, 200, 205, 300, 400, 500})
	states[4] = churnState{endpoints: states[3].endpoints, policies: npUpdate25, clusters: states[0].clusters}

	// Step 5: pod 62 added
	ep62 := maps.Clone(states[4].endpoints)
	np62 := maps.Clone(states[4].policies)
	podIP62 := "10.244.0.63"
	ep62["k8s/default/service-62:8080"] = buildBenchmarkEndpoint("k8s/default/service-62:8080", podIP62, 8080)
	np62["np-62"] = buildBenchmarkNetworkPolicy(1062, podIP62, []uint32{107, 203, 312})
	states[5] = churnState{endpoints: ep62, policies: np62, clusters: states[0].clusters}

	// Step 6: pod 12 removed
	epDel12 := maps.Clone(states[5].endpoints)
	npDel12 := maps.Clone(states[5].policies)
	delete(epDel12, "k8s/default/service-12:8080")
	delete(npDel12, "np-12")
	states[6] = churnState{endpoints: epDel12, policies: npDel12, clusters: states[0].clusters}

	// Step 7: pod 30 endpoint IP updated
	epUpdate30 := maps.Clone(states[6].endpoints)
	epUpdate30["k8s/default/service-30:8080"] = buildBenchmarkEndpoint("k8s/default/service-30:8080", "10.244.100.31", 8080)
	states[7] = churnState{endpoints: epUpdate30, policies: states[6].policies, clusters: states[0].clusters}

	calls := make([]benchCall, 0, len(states)*3)
	edsContext := []string{"cluster-ref-1,cluster-ref-2"}
	cdsContext := []string{"listener-ref-1"}

	for _, s := range states {
		calls = append(calls,
			benchCall{
				typeURL:        envoy_resource.EndpointType,
				resources:      s.endpoints,
				versionContext: edsContext,
			},
			benchCall{
				typeURL:        NetworkPolicyTypeURL,
				resources:      s.policies,
				versionContext: nil,
			},
			benchCall{
				typeURL:        envoy_resource.ClusterType,
				resources:      s.clusters,
				versionContext: cdsContext,
			},
		)
	}

	return calls
}

func BenchmarkResourceVersion(b *testing.B) {
	c := NewCache(slog.New(slog.DiscardHandler), false).(*cacheImpl)
	calls := buildBenchmarkChurnCalls()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		call := &calls[i%len(calls)]
		version, err := c.resourceVersion(call.typeURL, call.resources, call.versionContext...)
		if err != nil {
			b.Fatal(err)
		}
		benchResourceVersionSink = version
	}
}
