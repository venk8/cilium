// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ratelimitmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRatelimitMap_Strings(t *testing.T) {
	k := &Key{Usage: ICMPV6, Key: 100}
	assert.Equal(t, "1", k.String())

	v := &Value{LastTopup: 1234567890, Tokens: 500}
	assert.Equal(t, "1234567890 500", v.String())

	mk := &MetricsKey{Usage: EVENTS_MAP}
	assert.Equal(t, "2", mk.String())

	mv := &MetricsValue{Dropped: 42}
	assert.Equal(t, "42", mv.String())
}

func BenchmarkKey_String(b *testing.B) {
	k := &Key{Usage: ICMPV6, Key: 100}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k.String()
	}
}

func BenchmarkValue_String(b *testing.B) {
	v := &Value{LastTopup: 1234567890, Tokens: 500}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = v.String()
	}
}
