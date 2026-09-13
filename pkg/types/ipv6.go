// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "net/netip"

// IPv6 is the binary representation for encoding in binary structs.
type IPv6 [16]byte

func (v6 IPv6) IsZero() bool {
	return v6 == IPv6{}
}

func (v6 IPv6) Addr() netip.Addr {
	return netip.AddrFrom16(v6)
}

func (v6 IPv6) String() string {
	return v6.Addr().String()
}

// AppendTo appends the string representation of v6 to b and returns the resulting slice.
func (v6 IPv6) AppendTo(b []byte) []byte {
	return v6.Addr().AppendTo(b)
}

// FromAddr will populate the receiver with the specified address if and only
// if the provided address is a valid IPv6 address. Any other address,
// including the "invalid ip" value netip.Addr{} will zero the receiver.
func (v6 *IPv6) FromAddr(addr netip.Addr) {
	if addr.Is6() {
		*v6 = addr.As16()
	} else {
		*v6 = IPv6{}
	}
}
