// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "net/netip"

// IPv4 is the binary representation for encoding in binary structs.
type IPv4 [4]byte

func (v4 IPv4) IsZero() bool {
	return v4 == IPv4{}
}

func (v4 IPv4) Addr() netip.Addr {
	return netip.AddrFrom4(v4)
}

func (v4 IPv4) String() string {
	return v4.Addr().String()
}

// AppendTo appends the string representation of v4 to b and returns the resulting slice.
func (v4 IPv4) AppendTo(b []byte) []byte {
	return v4.Addr().AppendTo(b)
}

// FromAddr will populate the receiver with the specified address if and only
// if the provided address is a valid IPv4 address. Any other address,
// including the "invalid ip" value netip.Addr{} will zero the receiver.
func (v4 *IPv4) FromAddr(addr netip.Addr) {
	if addr.Is4() {
		*v4 = addr.As4()
	} else {
		*v4 = IPv4{}
	}
}
