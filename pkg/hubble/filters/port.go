// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func sourcePort(ev *v1.Event) (port uint16, ok bool) {
	flow := ev.GetFlow()
	if flow == nil {
		return 0, false
	}
	l4 := flow.GetL4()
	if l4 == nil {
		return 0, false
	}
	switch p := l4.Protocol.(type) {
	case *flowpb.Layer4_TCP:
		if p.TCP != nil {
			return uint16(p.TCP.SourcePort), true
		}
	case *flowpb.Layer4_UDP:
		if p.UDP != nil {
			return uint16(p.UDP.SourcePort), true
		}
	case *flowpb.Layer4_SCTP:
		if p.SCTP != nil {
			return uint16(p.SCTP.SourcePort), true
		}
	}
	return 0, false
}

func destinationPort(ev *v1.Event) (port uint16, ok bool) {
	flow := ev.GetFlow()
	if flow == nil {
		return 0, false
	}
	l4 := flow.GetL4()
	if l4 == nil {
		return 0, false
	}
	switch p := l4.Protocol.(type) {
	case *flowpb.Layer4_TCP:
		if p.TCP != nil {
			return uint16(p.TCP.DestinationPort), true
		}
	case *flowpb.Layer4_UDP:
		if p.UDP != nil {
			return uint16(p.UDP.DestinationPort), true
		}
	case *flowpb.Layer4_SCTP:
		if p.SCTP != nil {
			return uint16(p.SCTP.DestinationPort), true
		}
	}
	return 0, false
}

func filterByPort(portStrs []string, getPort func(*v1.Event) (port uint16, ok bool)) (FilterFunc, error) {
	ports := make([]uint16, 0, len(portStrs))
	for _, p := range portStrs {
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", p, err)
		}
		ports = append(ports, uint16(port))
	}

	switch len(ports) {
	case 1:
		p0 := ports[0]
		return func(ev *v1.Event) bool {
			if port, ok := getPort(ev); ok {
				return port == p0
			}
			return false
		}, nil
	case 2:
		p0, p1 := ports[0], ports[1]
		return func(ev *v1.Event) bool {
			if port, ok := getPort(ev); ok {
				return port == p0 || port == p1
			}
			return false
		}, nil
	default:
		return func(ev *v1.Event) bool {
			if port, ok := getPort(ev); ok {
				return slices.Contains(ports, port)
			}
			return false
		}, nil
	}
}

// PortFilter implements filtering based on L4 port numbers
type PortFilter struct{}

// OnBuildFilter builds a L4 port filter
func (p *PortFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetSourcePort() != nil {
		spf, err := filterByPort(ff.GetSourcePort(), sourcePort)
		if err != nil {
			return nil, fmt.Errorf("invalid source port filter: %w", err)
		}
		fs = append(fs, spf)
	}

	if ff.GetDestinationPort() != nil {
		dpf, err := filterByPort(ff.GetDestinationPort(), destinationPort)
		if err != nil {
			return nil, fmt.Errorf("invalid destination port filter: %w", err)
		}
		fs = append(fs, dpf)
	}

	return fs, nil
}
