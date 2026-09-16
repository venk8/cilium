// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tuple

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// tupleKey represents the key for {IPv4,IPv6} entries in the BPF conntrack map.
// Address field names are correct for return traffic, i.e., they are reversed
// compared to the original direction traffic.
type tupleKey[AddrT ipFamily] struct {
	DestAddr   AddrT           `align:"daddr"`
	SourceAddr AddrT           `align:"saddr"`
	DestPort   uint16          `align:"dport"`
	SourcePort uint16          `align:"sport"`
	NextHeader u8proto.U8proto `align:"nexthdr"`
	Flags      uint8           `align:"flags"`
}

// TupleKey4 represents the key for IPv4 entries in the BPF conntrack map.
// Address field names are correct for return traffic, i.e., they are reversed
// compared to the original direction traffic.
type TupleKey4 tupleKey[types.IPv4]

func (t *TupleKey4) GetDestAddr() netip.Addr {
	return t.DestAddr.Addr()
}

func (t *TupleKey4) GetDestPort() uint16 {
	return t.DestPort
}

func (t *TupleKey4) GetSourceAddr() netip.Addr {
	return t.SourceAddr.Addr()
}
func (t *TupleKey4) GetSourcePort() uint16 {
	return t.SourcePort
}

func (t *TupleKey4) GetNextHeader() u8proto.U8proto {
	return t.NextHeader
}

// ToNetwork converts TupleKey4 ports to network byte order.
func (k *TupleKey4) ToNetwork() TupleKey {
	n := *k
	n.SourcePort = byteorder.HostToNetwork16(n.SourcePort)
	n.DestPort = byteorder.HostToNetwork16(n.DestPort)
	return &n
}

// ToHost converts TupleKey4 ports to host byte order.
func (k *TupleKey4) ToHost() TupleKey {
	n := *k
	n.SourcePort = byteorder.NetworkToHost16(n.SourcePort)
	n.DestPort = byteorder.NetworkToHost16(n.DestPort)
	return &n
}

// GetFlags returns the tuple's flags.
func (k *TupleKey4) GetFlags() uint8 {
	return k.Flags
}

// String returns the tuple's string representation, doh.
func (k *TupleKey4) String() string {
	b := make([]byte, 0, 48)
	b = k.DestAddr.AppendTo(b)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(k.SourcePort), 10)
	b = append(b, ", "...)
	b = strconv.AppendUint(b, uint64(k.DestPort), 10)
	b = append(b, ", "...)
	b = strconv.AppendUint(b, uint64(k.NextHeader), 10)
	b = append(b, ", "...)
	b = strconv.AppendUint(b, uint64(k.Flags), 10)
	return string(b)
}

func (k *TupleKey4) New() bpf.MapKey { return &TupleKey4{} }

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k TupleKey4) Dump(sb *strings.Builder, reverse bool) bool {
	if k.NextHeader == 0 {
		return false
	}

	sb.WriteString(k.NextHeader.String())

	addrDest := k.DestAddr
	if reverse {
		addrDest = k.SourceAddr
	}

	var buf [32]byte
	if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(" IN ")
		sb.Write(addrDest.AppendTo(buf[:0]))
		sb.WriteByte(' ')
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.SourcePort), 10))
		sb.WriteByte(':')
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.DestPort), 10))
		sb.WriteByte(' ')
	} else {
		sb.WriteString(" OUT ")
		sb.Write(addrDest.AppendTo(buf[:0]))
		sb.WriteByte(' ')
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.DestPort), 10))
		sb.WriteByte(':')
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.SourcePort), 10))
		sb.WriteByte(' ')
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		sb.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		sb.WriteString("service ")
	}

	return true
}

// SwapAddresses swaps the tuple source and destination addresses.
func (t *TupleKey4) SwapAddresses() {
	tmp := t.SourceAddr
	t.SourceAddr = t.DestAddr
	t.DestAddr = tmp
}

// TupleKey4Global represents the key for IPv4 entries in the global BPF
// conntrack map.
type TupleKey4Global struct {
	TupleKey4
}

// GetFlags returns the tuple's flags.
func (k *TupleKey4Global) GetFlags() uint8 {
	return k.Flags
}

// String returns the tuple's string representation, doh.
func (k *TupleKey4Global) String() string {
	b := make([]byte, 0, 64)
	b = k.SourceAddr.AppendTo(b)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(k.SourcePort), 10)
	b = append(b, " --> "...)
	b = k.DestAddr.AppendTo(b)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(k.DestPort), 10)
	b = append(b, ", "...)
	b = strconv.AppendUint(b, uint64(k.NextHeader), 10)
	b = append(b, ", "...)
	b = strconv.AppendUint(b, uint64(k.Flags), 10)
	return string(b)
}

// ToNetwork converts ports to network byte order.
//
// This is necessary to prevent callers from implicitly converting
// the TupleKey4Global type here into a local key type in the nested
// TupleKey4 field.
func (k *TupleKey4Global) ToNetwork() TupleKey {
	return &TupleKey4Global{
		TupleKey4: *k.TupleKey4.ToNetwork().(*TupleKey4),
	}
}

// ToHost converts ports to host byte order.
//
// This is necessary to prevent callers from implicitly converting
// the TupleKey4Global type here into a local key type in the nested
// TupleKey4 field.
func (k *TupleKey4Global) ToHost() TupleKey {
	return &TupleKey4Global{
		TupleKey4: *k.TupleKey4.ToHost().(*TupleKey4),
	}
}

// Dump writes the contents of key to sb and returns true if the
// value for next header in the key is nonzero.
func (k TupleKey4Global) Dump(sb *strings.Builder, reverse bool) bool {
	if k.NextHeader == 0 {
		return false
	}

	sb.WriteString(k.NextHeader.String())

	addrSource := k.SourceAddr
	addrDest := k.DestAddr
	if reverse {
		addrSource, addrDest = addrDest, addrSource
	}

	var buf [32]byte
	if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(" IN ")
	} else {
		sb.WriteString(" OUT ")
	}
	sb.Write(addrSource.AppendTo(buf[:0]))
	sb.WriteByte(':')
	sb.Write(strconv.AppendUint(buf[:0], uint64(k.SourcePort), 10))
	sb.WriteString(" -> ")
	sb.Write(addrDest.AppendTo(buf[:0]))
	sb.WriteByte(':')
	sb.Write(strconv.AppendUint(buf[:0], uint64(k.DestPort), 10))
	sb.WriteByte(' ')

	if k.Flags&TUPLE_F_RELATED != 0 {
		sb.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		sb.WriteString("service ")
	}

	return true
}
