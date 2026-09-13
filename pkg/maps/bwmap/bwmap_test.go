// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bwmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEdt_StringsAndKeys(t *testing.T) {
	k := &EdtId{Id: 100, Direction: 1}
	assert.Equal(t, "100, 1", k.String())

	v := &EdtInfo{Bps: 1000000, Prio: 5}
	assert.Equal(t, "1000000, 5", v.String())

	idKey := EdtIDKey{EndpointID: 100, Direction: 1}
	expected := append(append([]byte{0, 100}, '+'), []byte{0, 1}...)
	assert.Equal(t, expected, []byte(idKey.Key()))
}

func BenchmarkEdtId_String(b *testing.B) {
	k := &EdtId{Id: 100, Direction: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k.String()
	}
}

func BenchmarkEdtInfo_String(b *testing.B) {
	v := &EdtInfo{Bps: 1000000, Prio: 5}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = v.String()
	}
}

func BenchmarkEdtIDKey_Key(b *testing.B) {
	idKey := EdtIDKey{EndpointID: 100, Direction: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = idKey.Key()
	}
}
