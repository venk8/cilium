// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package authmap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/datapath/linux/utime"
)

func TestAuthKey_String(t *testing.T) {
	k := AuthKey{
		LocalIdentity:  1234,
		RemoteIdentity: 5678,
		RemoteNodeID:   99,
		AuthType:       2,
	}
	assert.Equal(t, "localIdentity=1234, remoteIdentity=5678, remoteNodeID=99, authType=2", k.String())
}

func TestAuthInfo_String(t *testing.T) {
	exp := utime.TimeToUTime(time.Unix(1000, 0))
	info := AuthInfo{
		Expiration: exp,
	}
	assert.Equal(t, "expiration=\""+exp.String()+"\"", info.String())
}

func BenchmarkAuthKey_String(b *testing.B) {
	k := AuthKey{
		LocalIdentity:  1234,
		RemoteIdentity: 5678,
		RemoteNodeID:   99,
		AuthType:       2,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = k.String()
	}
}

func BenchmarkAuthInfo_String(b *testing.B) {
	exp := utime.TimeToUTime(time.Unix(1000, 0))
	info := AuthInfo{
		Expiration: exp,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = info.String()
	}
}
