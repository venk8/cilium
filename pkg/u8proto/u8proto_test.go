// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package u8proto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestU8proto(t *testing.T) {
	assert.Equal(t, "TCP", TCP.String())
	assert.Equal(t, "UDP", UDP.String())
	assert.Equal(t, "ICMP", ICMP.String())
	assert.Equal(t, "250", U8proto(250).String())

	p, err := ParseProtocol("tcp")
	assert.NoError(t, err)
	assert.Equal(t, TCP, p)

	p, err = ParseProtocol("TCP")
	assert.NoError(t, err)
	assert.Equal(t, TCP, p)

	p, err = ParseProtocol("udp")
	assert.NoError(t, err)
	assert.Equal(t, UDP, p)

	p, err = ParseProtocol("ICMP")
	assert.NoError(t, err)
	assert.Equal(t, ICMP, p)

	_, err = ParseProtocol("invalid_proto")
	assert.Error(t, err)

	p, err = FromNumber(6)
	assert.NoError(t, err)
	assert.Equal(t, TCP, p)

	_, err = FromNumber(250)
	assert.Error(t, err)
}

func BenchmarkU8proto_String_Known(b *testing.B) {
	p := TCP
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = p.String()
	}
}

func BenchmarkU8proto_String_Unknown(b *testing.B) {
	p := U8proto(250)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = p.String()
	}
}

func BenchmarkParseProtocol_Lower(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = ParseProtocol("tcp")
	}
}

func BenchmarkParseProtocol_Upper(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = ParseProtocol("TCP")
	}
}

func BenchmarkFromNumber(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = FromNumber(6)
	}
}
