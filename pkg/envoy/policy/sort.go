// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoypolicy

import (
	"cmp"
	"slices"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
)

// PortNetworkPolicySlice implements sort.Interface to sort a slice of
// *cilium.PortNetworkPolicy.
type PortNetworkPolicySlice []*cilium.PortNetworkPolicy

func (s PortNetworkPolicySlice) Len() int {
	return len(s)
}

// PortNetworkPolicyCmp compares two *cilium.PortNetworkPolicy instances.
func PortNetworkPolicyCmp(p1, p2 *cilium.PortNetworkPolicy) int {
	if c := cmp.Compare(p1.Protocol, p2.Protocol); c != 0 {
		return c
	}

	if c := cmp.Compare(p1.Port, p2.Port); c != 0 {
		return c
	}

	rules1, rules2 := p1.Rules, p2.Rules
	if c := cmp.Compare(len(rules1), len(rules2)); c != 0 {
		return c
	}
	// Assuming that the slices are sorted.
	for idx := range rules1 {
		if c := PortNetworkPolicyRuleCmp(rules1[idx], rules2[idx]); c != 0 {
			return c
		}
	}

	return 0
}

func (s PortNetworkPolicySlice) Less(i, j int) bool {
	return PortNetworkPolicyCmp(s[i], s[j]) < 0
}

func (s PortNetworkPolicySlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s PortNetworkPolicySlice) Sort() {
	SortPortNetworkPolicies(s)
}

// SortPortNetworkPolicies sorts the given slice in place and returns
// the sorted slice for convenience.
func SortPortNetworkPolicies(policies []*cilium.PortNetworkPolicy) []*cilium.PortNetworkPolicy {
	slices.SortFunc(policies, PortNetworkPolicyCmp)
	return policies
}

// PortNetworkPolicyRuleSlice implements sort.Interface to sort a slice of
// *cilium.PortNetworkPolicyRuleSlice.
type PortNetworkPolicyRuleSlice []*cilium.PortNetworkPolicyRule

// PortNetworkPolicyRuleCmp compares two *cilium.PortNetworkPolicyRule instances.
// L3-L4-only rules are less than L7 rules.
func PortNetworkPolicyRuleCmp(r1, r2 *cilium.PortNetworkPolicyRule) int {
	// First sort by precedence, highest precedence first
	if c := cmp.Compare(r2.Precedence, r1.Precedence); c != 0 {
		return c
	}

	http1, http2 := r1.GetHttpRules(), r2.GetHttpRules()
	switch {
	case http1 == nil && http2 != nil:
		return -1
	case http1 != nil && http2 == nil:
		return 1
	case http1 != nil && http2 != nil:
		httpRules1, httpRules2 := http1.HttpRules, http2.HttpRules
		if c := cmp.Compare(len(httpRules1), len(httpRules2)); c != 0 {
			return c
		}
		// Assuming that the slices are sorted.
		for idx := range httpRules1 {
			if c := HTTPNetworkPolicyRuleCmp(httpRules1[idx], httpRules2[idx]); c != 0 {
				return c
			}
		}
	}

	remotePolicies1, remotePolicies2 := r1.RemotePolicies, r2.RemotePolicies
	if c := cmp.Compare(len(remotePolicies1), len(remotePolicies2)); c != 0 {
		return c
	}
	// Assuming that the slices are sorted.
	for idx := range remotePolicies1 {
		if c := cmp.Compare(remotePolicies1[idx], remotePolicies2[idx]); c != 0 {
			return c
		}
	}

	return 0
}

// PortNetworkPolicyRuleLess reports whether the r1 rule should sort before
// the r2 rule.
// L3-L4-only rules are less than L7 rules.
func PortNetworkPolicyRuleLess(r1, r2 *cilium.PortNetworkPolicyRule) bool {
	return PortNetworkPolicyRuleCmp(r1, r2) < 0
}

func (s PortNetworkPolicyRuleSlice) Len() int {
	return len(s)
}

func (s PortNetworkPolicyRuleSlice) Less(i, j int) bool {
	return PortNetworkPolicyRuleLess(s[i], s[j])
}

func (s PortNetworkPolicyRuleSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s PortNetworkPolicyRuleSlice) Sort() {
	SortPortNetworkPolicyRules(s)
}

// SortPortNetworkPolicyRules sorts the given slice in place
// and returns the sorted slice for convenience.
func SortPortNetworkPolicyRules(rules []*cilium.PortNetworkPolicyRule) []*cilium.PortNetworkPolicyRule {
	slices.SortFunc(rules, PortNetworkPolicyRuleCmp)
	return rules
}

// HTTPNetworkPolicyRuleSlice implements sort.Interface to sort a slice of
// *cilium.HttpNetworkPolicyRule.
type HTTPNetworkPolicyRuleSlice []*cilium.HttpNetworkPolicyRule

// HTTPNetworkPolicyRuleCmp compares two *cilium.HttpNetworkPolicyRule instances.
func HTTPNetworkPolicyRuleCmp(r1, r2 *cilium.HttpNetworkPolicyRule) int {
	headers1, headers2 := r1.Headers, r2.Headers
	if c := cmp.Compare(len(headers1), len(headers2)); c != 0 {
		return c
	}
	// Assuming that the slices are sorted.
	for idx := range headers1 {
		if c := HeaderMatcherCmp(headers1[idx], headers2[idx]); c != 0 {
			return c
		}
	}

	return 0
}

// HTTPNetworkPolicyRuleLess reports whether the r1 rule should sort before the
// r2 rule.
func HTTPNetworkPolicyRuleLess(r1, r2 *cilium.HttpNetworkPolicyRule) bool {
	return HTTPNetworkPolicyRuleCmp(r1, r2) < 0
}

func (s HTTPNetworkPolicyRuleSlice) Len() int {
	return len(s)
}

func (s HTTPNetworkPolicyRuleSlice) Less(i, j int) bool {
	return HTTPNetworkPolicyRuleLess(s[i], s[j])
}

func (s HTTPNetworkPolicyRuleSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s HTTPNetworkPolicyRuleSlice) Sort() {
	SortHTTPNetworkPolicyRules(s)
}

// SortHTTPNetworkPolicyRules sorts the given slice.
func SortHTTPNetworkPolicyRules(rules []*cilium.HttpNetworkPolicyRule) {
	slices.SortFunc(rules, HTTPNetworkPolicyRuleCmp)
}

// HeaderMatcherSlice implements sort.Interface to sort a slice of
// *envoy_config_route.HeaderMatcher.
type HeaderMatcherSlice []*envoy_config_route.HeaderMatcher

// HeaderMatcherCmp compares two *envoy_config_route.HeaderMatcher instances.
func HeaderMatcherCmp(m1, m2 *envoy_config_route.HeaderMatcher) int {
	if c := cmp.Compare(m1.Name, m2.Name); c != 0 {
		return c
	}

	// Compare the header_match_specifier oneof field, by comparing each
	// possible field in the oneof individually:
	// - exactMatch
	// - regexMatch
	// - rangeMatch
	// - presentMatch
	// - prefixMatch
	// - suffixMatch
	// Use the getters to access the fields and return zero values when they
	// are not set.

	if c := cmp.Compare(m1.GetExactMatch(), m2.GetExactMatch()); c != 0 {
		return c
	}

	srm1 := m1.GetSafeRegexMatch()
	srm2 := m2.GetSafeRegexMatch()
	switch {
	case srm1 == nil && srm2 != nil:
		return -1
	case srm1 != nil && srm2 == nil:
		return 1
	case srm1 != nil && srm2 != nil:
		if c := cmp.Compare(srm1.Regex, srm2.Regex); c != 0 {
			return c
		}
	}

	rm1 := m1.GetRangeMatch()
	rm2 := m2.GetRangeMatch()
	switch {
	case rm1 == nil && rm2 != nil:
		return -1
	case rm1 != nil && rm2 == nil:
		return 1
	case rm1 != nil && rm2 != nil:
		if c := cmp.Compare(rm1.Start, rm2.Start); c != 0 {
			return c
		}
		if c := cmp.Compare(rm1.End, rm2.End); c != 0 {
			return c
		}
	}

	switch {
	case !m1.GetPresentMatch() && m2.GetPresentMatch():
		return -1
	case m1.GetPresentMatch() && !m2.GetPresentMatch():
		return 1
	}

	if c := cmp.Compare(m1.GetPrefixMatch(), m2.GetPrefixMatch()); c != 0 {
		return c
	}

	if c := cmp.Compare(m1.GetSuffixMatch(), m2.GetSuffixMatch()); c != 0 {
		return c
	}

	switch {
	case !m1.InvertMatch && m2.InvertMatch:
		return -1
	case m1.InvertMatch && !m2.InvertMatch:
		return 1
	}

	// Elements are equal.
	return 0
}

// HeaderMatcherLess reports whether the m1 matcher should sort before the m2
// matcher.
func HeaderMatcherLess(m1, m2 *envoy_config_route.HeaderMatcher) bool {
	return HeaderMatcherCmp(m1, m2) < 0
}

func (s HeaderMatcherSlice) Len() int {
	return len(s)
}

func (s HeaderMatcherSlice) Less(i, j int) bool {
	return HeaderMatcherLess(s[i], s[j])
}

func (s HeaderMatcherSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s HeaderMatcherSlice) Sort() {
	SortHeaderMatchers(s)
}

// SortHeaderMatchers sorts the given slice.
func SortHeaderMatchers(headers []*envoy_config_route.HeaderMatcher) {
	slices.SortFunc(headers, HeaderMatcherCmp)
}
