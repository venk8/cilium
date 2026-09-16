// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/config"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

var (
	fakeNodeAddressing = fakenode.NewAddressing()

	nodeConfig = config.Config{
		NodeIPv4:            ip.AddrFromIP(fakeNodeAddressing.IPv4().PrimaryExternal()),
		NodeIPv6:            ip.AddrFromIP(fakeNodeAddressing.IPv6().PrimaryExternal()),
		CiliumInternalIPv4:  ip.AddrFromIP(fakeNodeAddressing.IPv4().Router()),
		CiliumInternalIPv6:  ip.AddrFromIP(fakeNodeAddressing.IPv6().Router()),
		DeviceMTU:           calcMtu.DeviceMTU,
		RouteMTU:            calcMtu.RouteMTU,
		RoutePostEncryptMTU: calcMtu.RoutePostEncryptMTU,
	}
	mtuConfig = mtu.NewConfiguration(0, false, false, false, false)
	calcMtu   = mtuConfig.Calculate(100)
	nh        = linuxNodeHandler{
		nodeConfig: nodeConfig,
		datapathConfig: DatapathConfiguration{
			HostDevice: "host_device",
		},
	}
	cr1 = netip.MustParsePrefix("10.1.0.0/16")
)

func TestCreateNodeRoute(t *testing.T) {
	dpConfig := DatapathConfiguration{
		HostDevice: "host_device",
	}
	log := hivetest.Logger(t)

	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	nodeHandler := newNodeHandler(log, dpConfig, nil, kpr.KPRConfig{}, &fakeipsec.Agent{}, fakeipsec.Config{}, lns, newNodePolicy())
	nodeHandler.NodeConfigurationChanged(nodeConfig)

	c1 := netip.MustParsePrefix("10.10.0.0/16")
	generatedRoute, err := nodeHandler.createNodeRouteSpec(c1, false)
	require.NoError(t, err)
	require.Equal(t, *netipx.PrefixIPNet(c1), generatedRoute.Prefix)
	require.Equal(t, dpConfig.HostDevice, generatedRoute.Device)
	require.Equal(t, fakeNodeAddressing.IPv4().Router().To4(), generatedRoute.Nexthop.To4())
	require.Equal(t, fakeNodeAddressing.IPv4().Router().To4(), generatedRoute.Local.To4())

	c1 = netip.MustParsePrefix("beef:beef::/48")
	generatedRoute, err = nodeHandler.createNodeRouteSpec(c1, false)
	require.NoError(t, err)
	require.Equal(t, *netipx.PrefixIPNet(c1), generatedRoute.Prefix)
	require.Equal(t, dpConfig.HostDevice, generatedRoute.Device)
	require.Nil(t, generatedRoute.Nexthop)
	require.Equal(t, fakeNodeAddressing.IPv6().Router().To16(), generatedRoute.Local.To16())
}

func TestCreateNodeRouteSpecMtu(t *testing.T) {
	generatedRoute, err := nh.createNodeRouteSpec(cr1, false)

	require.NoError(t, err)
	require.NotEqual(t, 0, generatedRoute.MTU)

	generatedRoute, err = nh.createNodeRouteSpec(cr1, true)

	require.NoError(t, err)
	require.Equal(t, 0, generatedRoute.MTU)
}

func TestPrivilegedLocalRule(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	test := func(t *testing.T) {
		require.NoError(t, NodeEnsureLocalRoutingRule())

		// Expect at least one rule in the netns, with the first entry at pref 100
		// pointing at table 255.
		rules, err := route.ListRules(netlink.FAMILY_V4, nil)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(rules), 1)
		assert.Equal(t, linux_defaults.RulePriorityLocalLookup, rules[0].Priority)
		assert.Equal(t, unix.RT_TABLE_LOCAL, rules[0].Table)

		rules, err = route.ListRules(netlink.FAMILY_V6, nil)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(rules), 1)
		assert.Equal(t, linux_defaults.RulePriorityLocalLookup, rules[0].Priority)
		assert.Equal(t, unix.RT_TABLE_LOCAL, rules[0].Table)
	}

	ns.Do(func() error {
		// Install rules the first time.
		test(t)

		// Ensure idempotency.
		test(t)

		return nil
	})
}

func BenchmarkGetNodeIDForIP(b *testing.B) {
	dpConfig := DatapathConfiguration{HostDevice: "host_device"}
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	nodeHandler := newNodeHandler(hivetest.Logger(b), dpConfig, nil, kpr.KPRConfig{}, &fakeipsec.Agent{}, fakeipsec.Config{}, lns, newNodePolicy())
	nodeHandler.NodeConfigurationChanged(nodeConfig)

	targetIP := netip.MustParseAddr("192.0.2.10")
	nodeHandler.nodeIDsByIPs[targetIP.String()] = 42

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		id, ok := nodeHandler.getNodeIDForIP(targetIP)
		if !ok || id != 42 {
			b.Fatalf("unexpected result: id=%d ok=%v", id, ok)
		}
	}
}

func BenchmarkDumpNodeIDs(b *testing.B) {
	dpConfig := DatapathConfiguration{HostDevice: "host_device"}
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	nodeHandler := newNodeHandler(hivetest.Logger(b), dpConfig, nil, kpr.KPRConfig{}, &fakeipsec.Agent{}, fakeipsec.Config{}, lns, newNodePolicy())
	nodeHandler.NodeConfigurationChanged(nodeConfig)

	for i := 1; i <= 50; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i)
		nodeHandler.nodeIDsByIPs[ip] = uint16(i)
		setIPsByIDsMapping(nodeHandler.nodeIPsByIDs, uint16(i), ip)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dump := nodeHandler.DumpNodeIDs()
		if len(dump) != 50 {
			b.Fatalf("unexpected dump length: %d", len(dump))
		}
	}
}

func BenchmarkCreateNodeRouteSpec(b *testing.B) {
	dpConfig := DatapathConfiguration{HostDevice: "host_device"}
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	nodeHandler := newNodeHandler(hivetest.Logger(b), dpConfig, nil, kpr.KPRConfig{}, &fakeipsec.Agent{}, fakeipsec.Config{}, lns, newNodePolicy())
	nodeHandler.NodeConfigurationChanged(nodeConfig)

	c1 := netip.MustParsePrefix("10.10.0.0/16")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := nodeHandler.createNodeRouteSpec(c1, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUpdateDirectRoutes_Identical(b *testing.B) {
	dpConfig := DatapathConfiguration{HostDevice: "host_device"}
	lns := node.NewTestLocalNodeStore(node.LocalNode{})
	nodeHandler := newNodeHandler(hivetest.Logger(b), dpConfig, nil, kpr.KPRConfig{}, &fakeipsec.Agent{}, fakeipsec.Config{}, lns, newNodePolicy())
	nodeHandler.NodeConfigurationChanged(nodeConfig)

	cidrs := []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}
	nodeIP := net.ParseIP("192.0.2.1")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		err := nodeHandler.updateDirectRoutes(cidrs, cidrs, nodeIP, nodeIP, false, true, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

