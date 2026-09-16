// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"net"
	"testing"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestService4Key_String(t *testing.T) {
	key := NewService4Key(net.ParseIP("192.168.1.10"), 8080, u8proto.TCP, loadbalancer.ScopeExternal, 2).ToNetwork().(*Service4Key)
	expected := "192.168.1.10:8080/TCP (2)"
	if got := key.String(); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}

	keyInternal := NewService4Key(net.ParseIP("10.0.0.1"), 443, u8proto.UDP, loadbalancer.ScopeInternal, 0).ToNetwork().(*Service4Key)
	expectedInternal := "10.0.0.1:443/UDP/i (0)"
	if got := keyInternal.String(); got != expectedInternal {
		t.Fatalf("expected %q, got %q", expectedInternal, got)
	}
}

func TestService6Key_String(t *testing.T) {
	key := NewService6Key(net.ParseIP("fd00::1"), 8080, u8proto.TCP, loadbalancer.ScopeExternal, 2).ToNetwork().(*Service6Key)
	expected := "[fd00::1]:8080/TCP (2)"
	if got := key.String(); got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}

	keyInternal := NewService6Key(net.ParseIP("2001:db8::1"), 443, u8proto.UDP, loadbalancer.ScopeInternal, 0).ToNetwork().(*Service6Key)
	expectedInternal := "[2001:db8::1]:443/UDP/i (0)"
	if got := keyInternal.String(); got != expectedInternal {
		t.Fatalf("expected %q, got %q", expectedInternal, got)
	}
}

func TestServiceValues_String(t *testing.T) {
	val4 := &Service4Value{
		BackendID: 100,
		Count:     3,
		RevNat:    5,
		Flags:     0x01,
		Flags2:    0x02,
		QCount:    1,
	}
	expected4 := "100 3[1] (1280) [0x1 0x2]"
	if got := val4.String(); got != expected4 {
		t.Fatalf("Service4Value: expected %q, got %q", expected4, got)
	}

	val6 := &Service6Value{
		BackendID: 200,
		Count:     4,
		RevNat:    5,
		Flags:     0x10,
		Flags2:    0x20,
		QCount:    2,
	}
	expected6 := "200 4[2] (1280) [0x10 0x20]"
	if got := val6.String(); got != expected6 {
		t.Fatalf("Service6Value: expected %q, got %q", expected6, got)
	}
}

func TestBackendValues_String(t *testing.T) {
	addrCluster4 := cmtypes.MustParseAddrCluster("192.168.1.50@2")
	beVal4, err := NewBackend4ValueV3(addrCluster4, 8080, u8proto.TCP, loadbalancer.BackendStateActive, 0)
	if err != nil {
		t.Fatal(err)
	}
	expected4 := "TCP://192.168.1.50@2"
	if got := beVal4.String(); got != expected4 {
		t.Fatalf("Backend4ValueV3: expected %q, got %q", expected4, got)
	}

	addrCluster6 := cmtypes.MustParseAddrCluster("fd00::50@2")
	beVal6, err := NewBackend6ValueV3(addrCluster6, 8080, u8proto.TCP, loadbalancer.BackendStateActive, 0)
	if err != nil {
		t.Fatal(err)
	}
	expected6 := "TCP://fd00::50@2"
	if got := beVal6.String(); got != expected6 {
		t.Fatalf("Backend6ValueV3: expected %q, got %q", expected6, got)
	}
}

func TestRevNat_String(t *testing.T) {
	r4Key := NewRevNat4Key(12)
	expectedKey := "3072" // 12 in network byte order is 3072 in host order
	if got := r4Key.String(); got != expectedKey {
		t.Fatalf("RevNat4Key: expected %q, got %q", expectedKey, got)
	}

	r4Val := &RevNat4Value{Port: 8080}
	copy(r4Val.Address[:], net.ParseIP("10.0.0.1").To4())
	expectedVal4 := "10.0.0.1:36895"
	if got := r4Val.String(); got != expectedVal4 {
		t.Fatalf("RevNat4Value: expected %q, got %q", expectedVal4, got)
	}

	r6Key := NewRevNat6Key(12)
	expectedKey6 := "3072"
	if got := r6Key.String(); got != expectedKey6 {
		t.Fatalf("RevNat6Key: expected %q, got %q", expectedKey6, got)
	}

	r6Val := &RevNat6Value{Port: 8080}
	copy(r6Val.Address[:], net.ParseIP("fd00::1").To16())
	expectedVal6 := "[fd00::1]:36895"
	if got := r6Val.String(); got != expectedVal6 {
		t.Fatalf("RevNat6Value: expected %q, got %q", expectedVal6, got)
	}
}

func TestSourceRange_String(t *testing.T) {
	sr4 := &SourceRangeKey4{
		PrefixLen: 32 + lpmPrefixLen4,
		RevNATID:  12,
	}
	copy(sr4.Address[:], net.ParseIP("192.168.1.1").To4())
	expected4 := "192.168.1.1/32 (3072)"
	if got := sr4.String(); got != expected4 {
		t.Fatalf("SourceRangeKey4: expected %q, got %q", expected4, got)
	}

	sr6 := &SourceRangeKey6{
		PrefixLen: 128 + lpmPrefixLen6,
		RevNATID:  12,
	}
	copy(sr6.Address[:], net.ParseIP("fd00::1").To16())
	expected6 := "fd00::1/128 (3072)"
	if got := sr6.String(); got != expected6 {
		t.Fatalf("SourceRangeKey6: expected %q, got %q", expected6, got)
	}
}

func TestAffinity_String(t *testing.T) {
	affMatch := &AffinityMatchKey{BackendID: 42, RevNATID: 12}
	expectedMatch := "42 3072"
	if got := affMatch.String(); got != expectedMatch {
		t.Fatalf("AffinityMatchKey: expected %q, got %q", expectedMatch, got)
	}

	aff4 := &Affinity4Key{ClientID: 12345, NetNSCookie: 7, RevNATID: 88}
	expected4 := "12345 7 88"
	if got := aff4.String(); got != expected4 {
		t.Fatalf("Affinity4Key: expected %q, got %q", expected4, got)
	}

	affVal := &AffinityValue{BackendID: 10, LastUsed: 999999}
	expectedVal := "10 999999"
	if got := affVal.String(); got != expectedVal {
		t.Fatalf("AffinityValue: expected %q, got %q", expectedVal, got)
	}
}

func TestSockRevNat_String(t *testing.T) {
	k4 := &SockRevNat4Key{Cookie: 1234, Port: 8080}
	copy(k4.Address[:], net.ParseIP("10.0.0.1").To4())
	expectedK4 := "[10.0.0.1]:8080, 1234"
	if got := k4.String(); got != expectedK4 {
		t.Fatalf("SockRevNat4Key: expected %q, got %q", expectedK4, got)
	}

	v4 := &SockRevNat4Value{Port: 8080, RevNatIndex: 55}
	copy(v4.Address[:], net.ParseIP("10.0.0.1").To4())
	expectedV4 := "[10.0.0.1]:8080, 55"
	if got := v4.String(); got != expectedV4 {
		t.Fatalf("SockRevNat4Value: expected %q, got %q", expectedV4, got)
	}

	k6 := &SockRevNat6Key{Cookie: 5678, Port: 9090}
	copy(k6.Address[:], net.ParseIP("fd00::1").To16())
	expectedK6 := "[fd00::1]:9090, 5678"
	if got := k6.String(); got != expectedK6 {
		t.Fatalf("SockRevNat6Key: expected %q, got %q", expectedK6, got)
	}

	v6 := &SockRevNat6Value{Port: 9090, RevNatIndex: 77}
	copy(v6.Address[:], net.ParseIP("fd00::1").To16())
	expectedV6 := "[fd00::1]:9090, 77"
	if got := v6.String(); got != expectedV6 {
		t.Fatalf("SockRevNat6Value: expected %q, got %q", expectedV6, got)
	}
}

func TestMaglev_String(t *testing.T) {
	kOuter := &MaglevOuterKey{RevNatID: 100}
	if got := kOuter.String(); got != "100" {
		t.Fatalf("MaglevOuterKey: expected 100, got %q", got)
	}

	kInner := &MaglevInnerKey{Zero: 0}
	if got := kInner.String(); got != "0" {
		t.Fatalf("MaglevInnerKey: expected 0, got %q", got)
	}
}

func BenchmarkService4Key_String(b *testing.B) {
	key := NewService4Key(net.ParseIP("192.168.1.10"), 8080, u8proto.TCP, loadbalancer.ScopeInternal, 2)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = key.String()
	}
}

func BenchmarkService6Key_String(b *testing.B) {
	key := NewService6Key(net.ParseIP("fd00::1"), 8080, u8proto.TCP, loadbalancer.ScopeInternal, 2)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = key.String()
	}
}

func BenchmarkService4Value_String(b *testing.B) {
	val := &Service4Value{
		BackendID: 100,
		Count:     3,
		RevNat:    5,
		Flags:     0x01,
		Flags2:    0x02,
		QCount:    1,
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = val.String()
	}
}

func BenchmarkService6Value_String(b *testing.B) {
	val := &Service6Value{
		BackendID: 200,
		Count:     4,
		RevNat:    5,
		Flags:     0x10,
		Flags2:    0x20,
		QCount:    2,
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = val.String()
	}
}

func BenchmarkBackend4Value_String(b *testing.B) {
	addrCluster := cmtypes.MustParseAddrCluster("192.168.1.50@2")
	val, err := NewBackend4ValueV3(addrCluster, 8080, u8proto.TCP, loadbalancer.BackendStateActive, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = val.String()
	}
}

func BenchmarkBackend6Value_String(b *testing.B) {
	addrCluster := cmtypes.MustParseAddrCluster("fd00::50@2")
	val, err := NewBackend6ValueV3(addrCluster, 8080, u8proto.TCP, loadbalancer.BackendStateActive, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = val.String()
	}
}

func BenchmarkRevNat4Value_String(b *testing.B) {
	val := &RevNat4Value{Port: 8080}
	copy(val.Address[:], net.ParseIP("10.0.0.1").To4())
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = val.String()
	}
}

func BenchmarkRevNat6Value_String(b *testing.B) {
	val := &RevNat6Value{Port: 8080}
	copy(val.Address[:], net.ParseIP("fd00::1").To16())
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = val.String()
	}
}
