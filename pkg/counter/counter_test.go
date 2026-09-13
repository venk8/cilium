// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package counter

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCounter(t *testing.T) {
	sc := make(Counter[string])
	require.True(t, sc.Add("foo"))
	require.Len(t, sc, 1)
	require.False(t, sc.Add("foo"))
	require.Len(t, sc, 1)
	require.True(t, sc.Add("bar"))
	require.Len(t, sc, 2)
	nsc := sc.DeepCopy()
	require.Equal(t, nsc, sc)
	require.False(t, sc.Delete("foo"))
	require.Len(t, sc, 2)
	require.True(t, sc.Delete("bar"))
	require.Len(t, sc, 1)
	require.True(t, sc.Delete("foo"))
	require.Empty(t, sc)
	require.True(t, sc.Add("foo"))
	require.Len(t, sc, 1)

	ic := make(Counter[int])
	require.True(t, ic.Add(42))
	require.Len(t, ic, 1)
	require.False(t, ic.Add(42))
	require.Len(t, ic, 1)
	require.True(t, ic.Add(100))
	require.Len(t, ic, 2)
	nic := ic.DeepCopy()
	require.Equal(t, nic, ic)
	require.False(t, ic.Delete(42))
	require.Len(t, ic, 2)
	require.True(t, ic.Delete(100))
	require.Len(t, ic, 1)
	require.True(t, ic.Delete(42))
	require.Empty(t, ic)
	require.True(t, ic.Add(100))
	require.Len(t, ic, 1)

	ac := make(Counter[netip.Addr])
	require.True(t, ac.Add(netip.MustParseAddr("10.0.0.1")))
	require.Len(t, ac, 1)
	require.False(t, ac.Add(netip.MustParseAddr("10.0.0.1")))
	require.Len(t, ac, 1)
	require.True(t, ac.Add(netip.MustParseAddr("::1")))
	require.Len(t, ac, 2)
	require.True(t, ac.Add(netip.MustParseAddr("192.168.0.1")))
	require.Len(t, ac, 3)
	require.True(t, ac.Add(netip.MustParseAddr("::ffff:10.0.0.1")))
	require.Len(t, ac, 4)
	nac := ac.DeepCopy()
	require.Equal(t, nac, ac)
	require.False(t, ac.Delete(netip.MustParseAddr("10.0.0.1")))
	require.Len(t, ac, 4)
	require.True(t, ac.Delete(netip.MustParseAddr("10.0.0.1")))
	require.Len(t, ac, 3)
}

func TestIntCounter_ToBPFData(t *testing.T) {
	ic := make(IntCounter)
	ic.Add(10)
	ic.Add(50)
	ic.Add(20)
	ic.Add(40)
	ic.Add(30)
	require.Equal(t, []int{50, 40, 30, 20, 10}, ic.ToBPFData())
}

func BenchmarkIntCounter_ToBPFData(b *testing.B) {
	ic := make(IntCounter)
	for i := 0; i < 64; i++ {
		ic.Add(i * 7 % 100)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ic.ToBPFData()
	}
}
