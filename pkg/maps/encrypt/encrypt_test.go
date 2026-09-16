// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptString(t *testing.T) {
	k := EncryptKey{Key: 42}
	assert.Equal(t, "42", k.String())

	v := EncryptValue{KeyID: 7}
	assert.Equal(t, "7", v.String())
}

func BenchmarkEncryptKey_String(b *testing.B) {
	k := EncryptKey{Key: 42}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = k.String()
	}
}

func BenchmarkEncryptValue_String(b *testing.B) {
	v := EncryptValue{KeyID: 7}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.String()
	}
}
