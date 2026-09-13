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

// TupleKey6 represents the key for IPv6 entries in the BPF conntrack map.
// Address field names are correct for return traffic, i.e., they are reversed
// compared to the original direction traffic.
type TupleKey6 tupleKey[types.IPv6]

func (t *TupleKey6) GetDestAddr() netip.Addr {
	return t.DestAddr.Addr()
}

func (t *TupleKey6) GetDestPort() uint16 {
	return t.DestPort
}

func (t *TupleKey6) GetSourceAddr() netip.Addr {
	return t.SourceAddr.Addr()
}
func (t *TupleKey6) GetSourcePort() uint16 {
	return t.SourcePort
}

func (t *TupleKey6) GetNextHeader() u8proto.U8proto {
	return t.NextHeader
}

// ToNetwork converts TupleKey6 ports to network byte order.
func (k *TupleKey6) ToNetwork() TupleKey {
	n := *k
	n.SourcePort = byteorder.HostToNetwork16(n.SourcePort)
	n.DestPort = byteorder.HostToNetwork16(n.DestPort)
	return &n
}

// ToHost converts TupleKey6 ports to network byte order.
func (k *TupleKey6) ToHost() TupleKey {
	n := *k
	n.SourcePort = byteorder.NetworkToHost16(n.SourcePort)
	n.DestPort = byteorder.NetworkToHost16(n.DestPort)
	return &n
}

// GetFlags returns the tuple's flags.
func (k *TupleKey6) GetFlags() uint8 {
	return k.Flags
}

// String returns the tuple's string representation, doh.
func (k *TupleKey6) String() string {
	b := make([]byte, 0, 80)
	b = append(b, '[')
	b = k.DestAddr.AppendTo(b)
	b = append(b, "]:"...)
	b = strconv.AppendUint(b, uint64(k.SourcePort), 10)
	b = append(b, ", "...)
	b = strconv.AppendUint(b, uint64(k.DestPort), 10)
	b = append(b, ", "...)
	b = strconv.AppendUint(b, uint64(k.NextHeader), 10)
	b = append(b, ", "...)
	b = strconv.AppendUint(b, uint64(k.Flags), 10)
	return string(b)
}

func (k *TupleKey6) New() bpf.MapKey { return &TupleKey6{} }

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k TupleKey6) Dump(sb *strings.Builder, reverse bool) bool {
	if k.NextHeader == 0 {
		return false
	}

	sb.WriteString(k.NextHeader.String())

	addrDest := k.DestAddr
	if reverse {
		addrDest = k.SourceAddr
	}

	var buf [48]byte
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
func (t *TupleKey6) SwapAddresses() {
	tmp := t.SourceAddr
	t.SourceAddr = t.DestAddr
	t.DestAddr = tmp
}

// TupleKey6Global represents the key for IPv6 entries in the global BPF conntrack map.
type TupleKey6Global struct {
	TupleKey6
}

// GetFlags returns the tuple's flags.
func (k *TupleKey6Global) GetFlags() uint8 {
	return k.Flags
}

// String returns the tuple's string representation, doh.
func (k *TupleKey6Global) String() string {
	b := make([]byte, 0, 112)
	b = append(b, '[')
	b = k.SourceAddr.AppendTo(b)
	b = append(b, "]:"...)
	b = strconv.AppendUint(b, uint64(k.SourcePort), 10)
	b = append(b, " --> ["...)
	b = k.DestAddr.AppendTo(b)
	b = append(b, "]:"...)
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
// the TupleKey6Global type here into a local key type in the nested
// TupleKey6 field.
func (k *TupleKey6Global) ToNetwork() TupleKey {
	return &TupleKey6Global{
		TupleKey6: *k.TupleKey6.ToNetwork().(*TupleKey6),
	}
}

// ToHost converts ports to host byte order.
//
// This is necessary to prevent callers from implicitly converting
// the TupleKey6Global type here into a local key type in the nested
// TupleKey6 field.
func (k *TupleKey6Global) ToHost() TupleKey {
	return &TupleKey6Global{
		TupleKey6: *k.TupleKey6.ToHost().(*TupleKey6),
	}
}

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k TupleKey6Global) Dump(sb *strings.Builder, reverse bool) bool {
	if k.NextHeader == 0 {
		return false
	}

	sb.WriteString(k.NextHeader.String())

	addrSource := k.SourceAddr
	addrDest := k.DestAddr
	if reverse {
		addrSource, addrDest = addrDest, addrSource
	}

	var buf [48]byte
	if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(" IN [")
	} else {
		sb.WriteString(" OUT [")
	}
	sb.Write(addrSource.AppendTo(buf[:0]))
	sb.WriteString("]:")
	sb.Write(strconv.AppendUint(buf[:0], uint64(k.SourcePort), 10))
	sb.WriteString(" -> [")
	sb.Write(addrDest.AppendTo(buf[:0]))
	sb.WriteString("]:")
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
