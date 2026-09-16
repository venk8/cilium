// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
)

func TestLabelSelectorToRequirements(t *testing.T) {
	labelSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			"any.foo": "bar",
			"k8s.baz": "alice",
		},
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			{
				Key:      "any.foo",
				Operator: "NotIn",
				Values:   []string{"default"},
			},
		},
	}

	expRequirements := Requirements{}
	req := NewRequirement("any.foo", selection.Equals, []string{"bar"})
	expRequirements = append(expRequirements, req)
	req = NewRequirement("any.foo", selection.NotIn, []string{"default"})
	expRequirements = append(expRequirements, req)
	req = NewRequirement("k8s.baz", selection.Equals, []string{"alice"})
	expRequirements = append(expRequirements, req)

	require.Equal(t, expRequirements, LabelSelectorToRequirements(labelSelector))
}

func BenchmarkLabelSelectorToRequirements(b *testing.B) {
	labelSelector := &slim_metav1.LabelSelector{
		MatchLabels: map[string]string{
			"any.foo": "bar",
			"k8s.baz": "alice",
			"k8s.app": "frontend",
			"k8s.env": "prod",
		},
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			{
				Key:      "any.foo",
				Operator: "NotIn",
				Values:   []string{"default"},
			},
			{
				Key:      "k8s.tier",
				Operator: "In",
				Values:   []string{"backend", "cache"},
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = LabelSelectorToRequirements(labelSelector)
	}
}

func BenchmarkRequirements_Sort(b *testing.B) {
	reqs := Requirements{
		NewRequirement("k8s.io/pod-name", selection.Equals, []string{"pod-1"}),
		NewRequirement("k8s.app", selection.Equals, []string{"frontend"}),
		NewRequirement("any.foo", selection.Equals, []string{"bar"}),
		NewRequirement("k8s.tier", selection.In, []string{"backend"}),
		NewRequirement("k8s.env", selection.Equals, []string{"prod"}),
		NewRequirement("any.zoo", selection.NotIn, []string{"default"}),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := make(Requirements, len(reqs))
		copy(r, reqs)
		r.Sort()
	}
}

func BenchmarkRequirements_SortLegacy(b *testing.B) {
	reqs := Requirements{
		NewRequirement("k8s.io/pod-name", selection.Equals, []string{"pod-1"}),
		NewRequirement("k8s.app", selection.Equals, []string{"frontend"}),
		NewRequirement("any.foo", selection.Equals, []string{"bar"}),
		NewRequirement("k8s.tier", selection.In, []string{"backend"}),
		NewRequirement("k8s.env", selection.Equals, []string{"prod"}),
		NewRequirement("any.zoo", selection.NotIn, []string{"default"}),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := make(Requirements, len(reqs))
		copy(r, reqs)
		sort.Sort(r)
	}
}
