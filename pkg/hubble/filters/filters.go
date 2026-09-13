// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"log/slog"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

// FilterFunc is the function will be used to filter the given data.
// Should return true if the filter is hit, false otherwise.
type FilterFunc func(ev *v1.Event) bool

// FilterFuncs is a combination of multiple filters, typically applied together.
type FilterFuncs []FilterFunc

// Apply filters the flow with the given white- and blacklist. Returns true
// if the flow should be included in the result.
func Apply(whitelist, blacklist FilterFuncs, ev *v1.Event) bool {
	if len(whitelist) > 0 && !whitelist.MatchOne(ev) {
		return false
	}
	if len(blacklist) > 0 && !blacklist.MatchNone(ev) {
		return false
	}
	return true
}

// MatchAll returns true if all the filters match the provided data, i.e. AND.
func (fs FilterFuncs) MatchAll(ev *v1.Event) bool {
	switch len(fs) {
	case 0:
		return true
	case 1:
		return fs[0](ev)
	case 2:
		return fs[0](ev) && fs[1](ev)
	default:
		for _, f := range fs {
			if !f(ev) {
				return false
			}
		}
		return true
	}
}

// MatchOne returns true if at least one of the filters match the provided data or
// if no filters are specified, i.e. OR.
func (fs FilterFuncs) MatchOne(ev *v1.Event) bool {
	switch len(fs) {
	case 0:
		return true
	case 1:
		return fs[0](ev)
	case 2:
		return fs[0](ev) || fs[1](ev)
	default:
		for _, f := range fs {
			if f(ev) {
				return true
			}
		}
		return false
	}
}

// MatchNone returns true if none of the filters match the provided data or
// if no filters are specified, i.e. NOR
func (fs FilterFuncs) MatchNone(ev *v1.Event) bool {
	switch len(fs) {
	case 0:
		return true
	case 1:
		return !fs[0](ev)
	case 2:
		return !fs[0](ev) && !fs[1](ev)
	default:
		for _, f := range fs {
			if f(ev) {
				return false
			}
		}
		return true
	}
}

// OnBuildFilter is invoked while building a flow filter
type OnBuildFilter interface {
	OnBuildFilter(context.Context, *flowpb.FlowFilter) ([]FilterFunc, error)
}

// OnBuildFilterFunc implements OnBuildFilter for a single function
type OnBuildFilterFunc func(context.Context, *flowpb.FlowFilter) ([]FilterFunc, error)

// OnBuildFilter is invoked while building a flow filter
func (f OnBuildFilterFunc) OnBuildFilter(ctx context.Context, flow *flowpb.FlowFilter) ([]FilterFunc, error) {
	return f(ctx, flow)
}

// BuildFilter builds a filter based on a FlowFilter. It returns:
//   - the FilterFunc to be used to filter packets based on the requested
//     FlowFilter;
//   - an error in case something went wrong.
func BuildFilter(ctx context.Context, ff *flowpb.FlowFilter, auxFilters []OnBuildFilter) (FilterFuncs, error) {
	var fs []FilterFunc

	for _, f := range auxFilters {
		fl, err := f.OnBuildFilter(ctx, ff)
		if err != nil {
			return nil, err
		}
		if fl != nil {
			fs = append(fs, fl...)
		}
	}

	return fs, nil
}

// BuildFilterList constructs a list of filter functions representing the list
// of FlowFilter. It returns:
//   - the FilterFunc to be used to filter packets based on the requested
//     FlowFilter;
//   - an error in case something went wrong.
func BuildFilterList(ctx context.Context, ff []*flowpb.FlowFilter, auxFilters []OnBuildFilter) (FilterFuncs, error) {
	filterList := make([]FilterFunc, 0, len(ff))

	for _, flowFilter := range ff {
		// Build filter matching on all requirements of the FlowFilter
		tf, err := BuildFilter(ctx, flowFilter, auxFilters)
		if err != nil {
			return nil, err
		}

		// All filters representing a FlowFilter must match
		switch len(tf) {
		case 0:
			filterList = append(filterList, func(ev *v1.Event) bool { return true })
		case 1:
			filterList = append(filterList, tf[0])
		default:
			filterList = append(filterList, tf.MatchAll)
		}
	}

	return filterList, nil
}

// DefaultFilters is the list of default filters
func DefaultFilters(log *slog.Logger) []OnBuildFilter {
	return []OnBuildFilter{
		&UUIDFilter{},
		&EventTypeFilter{},
		&VerdictFilter{},
		&DropReasonDescFilter{},
		&ReplyFilter{},
		&EncryptedFilter{},
		&IdentityFilter{},
		&ProtocolFilter{},
		&IPFilter{},
		&PodFilter{},
		&WorkloadFilter{},
		&ServiceFilter{},
		&FQDNFilter{},
		&LabelsFilter{},
		&PortFilter{},
		&HTTPFilter{},
		&TCPFilter{},
		&NodeNameFilter{},
		&ClusterNameFilter{},
		&IPVersionFilter{},
		&TraceIDFilter{},
		&TrafficDirectionFilter{},
		&CELExpressionFilter{log: log},
		&NetworkInterfaceFilter{},
		&IPTraceIDFilter{},
	}
}
