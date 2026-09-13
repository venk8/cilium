// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"fmt"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

const (
	protoICMP   uint16 = 1 << 0
	protoICMPv4 uint16 = 1 << 1
	protoICMPv6 uint16 = 1 << 2
	protoTCP    uint16 = 1 << 3
	protoUDP    uint16 = 1 << 4
	protoSCTP   uint16 = 1 << 5
	protoVRRP   uint16 = 1 << 6
	protoIGMP   uint16 = 1 << 7
	protoDNS    uint16 = 1 << 8
	protoHTTP   uint16 = 1 << 9
)

func filterByProtocol(protocols []string) (FilterFunc, error) {
	var l4Mask, l7Mask uint16
	for _, p := range protocols {
		proto := strings.ToLower(p)
		switch proto {
		case "icmp":
			l4Mask |= protoICMP
		case "icmpv4":
			l4Mask |= protoICMPv4
		case "icmpv6":
			l4Mask |= protoICMPv6
		case "tcp":
			l4Mask |= protoTCP
		case "udp":
			l4Mask |= protoUDP
		case "sctp":
			l4Mask |= protoSCTP
		case "vrrp":
			l4Mask |= protoVRRP
		case "igmp":
			l4Mask |= protoIGMP
		case "dns":
			l7Mask |= protoDNS
		case "http":
			l7Mask |= protoHTTP
		default:
			return nil, fmt.Errorf("unknown protocol: %q", p)
		}
	}

	return func(ev *v1.Event) bool {
		flow := ev.GetFlow()
		if flow == nil {
			return false
		}
		if l4Mask != 0 {
			if l4 := flow.GetL4(); l4 != nil {
				switch p := l4.Protocol.(type) {
				case *flowpb.Layer4_TCP:
					if l4Mask&protoTCP != 0 && p.TCP != nil {
						return true
					}
				case *flowpb.Layer4_UDP:
					if l4Mask&protoUDP != 0 && p.UDP != nil {
						return true
					}
				case *flowpb.Layer4_ICMPv4:
					if l4Mask&(protoICMP|protoICMPv4) != 0 && p.ICMPv4 != nil {
						return true
					}
				case *flowpb.Layer4_ICMPv6:
					if l4Mask&(protoICMP|protoICMPv6) != 0 && p.ICMPv6 != nil {
						return true
					}
				case *flowpb.Layer4_SCTP:
					if l4Mask&protoSCTP != 0 && p.SCTP != nil {
						return true
					}
				case *flowpb.Layer4_VRRP:
					if l4Mask&protoVRRP != 0 && p.VRRP != nil {
						return true
					}
				case *flowpb.Layer4_IGMP:
					if l4Mask&protoIGMP != 0 && p.IGMP != nil {
						return true
					}
				}
			}
		}

		if l7Mask != 0 {
			if l7 := flow.GetL7(); l7 != nil {
				switch r := l7.Record.(type) {
				case *flowpb.Layer7_Dns:
					if l7Mask&protoDNS != 0 && r.Dns != nil {
						return true
					}
				case *flowpb.Layer7_Http:
					if l7Mask&protoHTTP != 0 && r.Http != nil {
						return true
					}
				}
			}
		}

		return false
	}, nil
}

// ProtocolFilter implements filtering based on L4 protocol
type ProtocolFilter struct{}

// OnBuildFilter builds a L4 protocol filter
func (p *ProtocolFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetProtocol() != nil {
		pf, err := filterByProtocol(ff.GetProtocol())
		if err != nil {
			return nil, fmt.Errorf("invalid protocol filter: %w", err)
		}
		fs = append(fs, pf)
	}

	return fs, nil
}
