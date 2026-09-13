// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"fmt"
	"testing"

	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
)

func BenchmarkByKeySort(b *testing.B) {
	const n = 16
	base := make([]Requirement, n)
	for i := 0; i < n; i++ {
		base[i] = Requirement{
			key:       fmt.Sprintf("k8s.io/label-%d", (i*7)%n),
			operator:  selection.Equals,
			strValues: []string{fmt.Sprintf("value-%d", i)},
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reqs := make([]Requirement, n)
		copy(reqs, base)
		ByKey(reqs).Sort()
	}
}

func BenchmarkSelectorFromValidatedSet(b *testing.B) {
	ls := make(Set, 16)
	for i := 0; i < 16; i++ {
		ls[fmt.Sprintf("key-%d", i)] = fmt.Sprintf("val-%d", i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SelectorFromValidatedSet(ls)
	}
}

func BenchmarkSetString(b *testing.B) {
	ls := make(Set, 16)
	for i := 0; i < 16; i++ {
		ls[fmt.Sprintf("key-%d", i)] = fmt.Sprintf("val-%d", i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ls.String()
	}
}
