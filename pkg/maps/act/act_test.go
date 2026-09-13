// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package act

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestActiveConnectionTrackerString(t *testing.T) {
	k := &ActiveConnectionTrackerKey{
		SvcID: 0x1234,
		Zone:  1,
	}
	assert.NotEmpty(t, k.String())

	v := &ActiveConnectionTrackerValue{
		Opened: 100,
		Closed: 50,
	}
	assert.Equal(t, "+100 -50", v.String())
}

func BenchmarkActiveConnectionTrackerKey_String(b *testing.B) {
	k := &ActiveConnectionTrackerKey{
		SvcID: 0x1234,
		Zone:  1,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = k.String()
	}
}

func BenchmarkActiveConnectionTrackerValue_String(b *testing.B) {
	v := &ActiveConnectionTrackerValue{
		Opened: 100,
		Closed: 50,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.String()
	}
}
