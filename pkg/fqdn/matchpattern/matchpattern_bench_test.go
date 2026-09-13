// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package matchpattern

import (
	"testing"
)

func BenchmarkToAnchoredRegexp(b *testing.B) {
	patterns := []string{
		"cilium.io.",
		"*.cilium.io.",
		"test.*.cilium.io.",
		"**.cilium.io.",
		"*",
		"**",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		for _, p := range patterns {
			_ = ToAnchoredRegexp(p)
		}
	}
}

func BenchmarkValidate(b *testing.B) {
	patterns := []string{
		"cilium.io.",
		"*.cilium.io.",
		"test.*.cilium.io.",
		"**.cilium.io.",
		"*",
		"**",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		for _, p := range patterns {
			_, _ = Validate(p)
		}
	}
}

func BenchmarkSanitize(b *testing.B) {
	patterns := []string{
		"cilium.io",
		"*.cilium.io",
		"test.*.cilium.io",
		"**.cilium.io",
		"*",
		"**",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		for _, p := range patterns {
			_ = Sanitize(p)
		}
	}
}
