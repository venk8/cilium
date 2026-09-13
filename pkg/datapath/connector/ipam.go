// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/defaults"
)

// IPv6Gateway returns the IPv6 gateway address for endpoints.
func IPv6Gateway(addr *models.NodeAddressing) string {
	// The host's IP is the gateway address
	return addr.IPv6.IP
}

// IPv4Gateway returns the IPv4 gateway address for endpoints.
func IPv4Gateway(addr *models.NodeAddressing) string {
	// The host's IP is the gateway address
	return addr.IPv4.IP
}

// IPv6Routes returns IPv6 routes to be installed in endpoint's networking namespace.
func IPv6Routes(addr *models.NodeAddressing, linkMTU int) ([]route.Route, error) {
	ip, err := netip.ParseAddr(addr.IPv6.IP)
	if err != nil {
		return nil, fmt.Errorf("Invalid IP address: %s", addr.IPv6.IP)
	}
	stdIP := net.IP(ip.AsSlice())
	return []route.Route{
		{
			Prefix: net.IPNet{
				IP:   stdIP,
				Mask: defaults.ContainerIPv6Mask,
			},
		},
		{
			Prefix:  defaults.IPv6DefaultRoute,
			Nexthop: &stdIP,
			MTU:     linkMTU,
		},
	}, nil
}

// IPv4Routes returns IPv4 routes to be installed in endpoint's networking namespace.
func IPv4Routes(addr *models.NodeAddressing, linkMTU int) ([]route.Route, error) {
	ip, err := netip.ParseAddr(addr.IPv4.IP)
	if err != nil {
		return nil, fmt.Errorf("Invalid IP address: %s", addr.IPv4.IP)
	}
	stdIP := net.IP(ip.AsSlice())
	return []route.Route{
		{
			Prefix: net.IPNet{
				IP:   stdIP,
				Mask: defaults.ContainerIPv4Mask,
			},
		},
		{
			Prefix:  defaults.IPv4DefaultRoute,
			Nexthop: &stdIP,
			MTU:     linkMTU,
		},
	}, nil
}

// SufficientAddressing returns an error if the provided NodeAddressing does
// not provide sufficient information to derive all IPAM required settings.
func SufficientAddressing(addr *models.NodeAddressing) error {
	if addr == nil {
		return fmt.Errorf("Cilium daemon did not provide addressing information")
	}

	if addr.IPv6 != nil && addr.IPv6.IP != "" {
		return nil
	}

	if addr.IPv4 != nil && addr.IPv4.IP != "" {
		return nil
	}

	return fmt.Errorf("Either IPv4 or IPv6 addressing must be provided")
}
