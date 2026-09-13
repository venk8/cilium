// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractCommonName(t *testing.T) {
	assert.Equal(t, "calls", extractCommonName("cilium_calls_1157"))
	assert.Equal(t, "calls", extractCommonName("cilium_calls_netdev_ns_1"))
	assert.Equal(t, "calls", extractCommonName("cilium_calls_overlay_2"))
	assert.Equal(t, "ct4_global", extractCommonName("cilium_ct4_global"))
	assert.Equal(t, "ct_any4_global", extractCommonName("cilium_ct_any4_global"))
	assert.Equal(t, "events", extractCommonName("cilium_events"))
	assert.Equal(t, "ipcache", extractCommonName("cilium_ipcache"))
	assert.Equal(t, "lb4_reverse_nat", extractCommonName("cilium_lb4_reverse_nat"))
	assert.Equal(t, "lb4_rr_seq", extractCommonName("cilium_lb4_rr_seq"))
	assert.Equal(t, "lb4_services", extractCommonName("cilium_lb4_services"))
	assert.Equal(t, "lxc", extractCommonName("cilium_lxc"))
	assert.Equal(t, "metrics", extractCommonName("cilium_metrics"))
	assert.Equal(t, "policy", extractCommonName("cilium_policy"))
	assert.Equal(t, "policy", extractCommonName("cilium_policy_1157"))
	assert.Equal(t, "policy", extractCommonName("cilium_policy_reserved_1"))
	assert.Equal(t, "policy", extractCommonName("cilium_policy_v3_1157"))
	assert.Equal(t, "policy", extractCommonName("cilium_policy_v3_reserved_1"))
	assert.Equal(t, "tunnel_map", extractCommonName("cilium_tunnel_map"))
}

func BenchmarkExtractCommonName(b *testing.B) {
	names := []string{
		"cilium_calls_1157",
		"cilium_calls_netdev_ns_1",
		"cilium_calls_overlay_2",
		"cilium_ct4_global",
		"cilium_ct_any4_global",
		"cilium_events",
		"cilium_ipcache",
		"cilium_lb4_reverse_nat",
		"cilium_lb4_rr_seq",
		"cilium_lb4_services",
		"cilium_lxc",
		"cilium_metrics",
		"cilium_policy",
		"cilium_policy_1157",
		"cilium_policy_reserved_1",
		"cilium_policy_v3_1157",
		"cilium_policy_v3_reserved_1",
		"cilium_tunnel_map",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, name := range names {
			_ = extractCommonName(name)
		}
	}
}

