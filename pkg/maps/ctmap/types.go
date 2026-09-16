// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
)

// mapType is a type of connection tracking map.
type mapType int

const (
	// map types which correspond to a
	// combination of the following attributes:
	// * IPv4 or IPv6;
	// * TCP or non-TCP (shortened to Any)
	mapTypeIPv4TCPGlobal mapType = iota
	mapTypeIPv6TCPGlobal
	mapTypeIPv4AnyGlobal
	mapTypeIPv6AnyGlobal
	mapTypeMax
)

// String renders the map type into a user-readable string.
func (m mapType) String() string {
	switch m {
	case mapTypeIPv4TCPGlobal:
		return "Global IPv4 TCP CT map"
	case mapTypeIPv6TCPGlobal:
		return "Global IPv6 TCP CT map"
	case mapTypeIPv4AnyGlobal:
		return "Global IPv4 non-TCP CT map"
	case mapTypeIPv6AnyGlobal:
		return "Global IPv6 non-TCP CT map"
	}
	return fmt.Sprintf("Unknown (%d)", int(m))
}

func (m mapType) name() string {
	switch m {
	case mapTypeIPv4TCPGlobal:
		return "tcp4"
	case mapTypeIPv6TCPGlobal:
		return "tcp6"
	case mapTypeIPv4AnyGlobal:
		return "any4"
	case mapTypeIPv6AnyGlobal:
		return "any6"
	default:
		panic("Unexpected map type " + m.String())
	}
}

func (m mapType) isIPv4() bool {
	switch m {
	case mapTypeIPv4TCPGlobal, mapTypeIPv4AnyGlobal:
		return true
	}
	return false
}

func (m mapType) isIPv6() bool {
	switch m {
	case mapTypeIPv6TCPGlobal, mapTypeIPv6AnyGlobal:
		return true
	}
	return false
}

func (m mapType) isTCP() bool {
	switch m {
	case mapTypeIPv4TCPGlobal, mapTypeIPv6TCPGlobal:
		return true
	}
	return false
}

func (m mapType) key() bpf.MapKey {
	switch m {
	case mapTypeIPv4TCPGlobal, mapTypeIPv4AnyGlobal:
		return &CtKey4Global{}
	case mapTypeIPv6TCPGlobal, mapTypeIPv6AnyGlobal:
		return &CtKey6Global{}
	default:
		panic("Unexpected map type " + m.String())
	}
}

func (m mapType) value() bpf.MapValue {
	return &CtEntry{}
}

func (m mapType) maxEntries() int {
	switch m {
	case mapTypeIPv4TCPGlobal, mapTypeIPv6TCPGlobal:
		if option.Config.CTMapEntriesGlobalTCP != 0 {
			return option.Config.CTMapEntriesGlobalTCP
		}
		return option.CTMapEntriesGlobalTCPDefault

	case mapTypeIPv4AnyGlobal, mapTypeIPv6AnyGlobal:
		if option.Config.CTMapEntriesGlobalAny != 0 {
			return option.Config.CTMapEntriesGlobalAny
		}
		return option.CTMapEntriesGlobalAnyDefault

	default:
		panic("Unexpected map type " + m.String())
	}
}

type CtKey interface {
	bpf.MapKey

	// ToNetwork converts fields to network byte order.
	ToNetwork() CtKey

	// ToHost converts fields to host byte order.
	ToHost() CtKey

	// Dump contents of key to sb. Returns true if successful.
	Dump(sb *strings.Builder, reverse bool) bool

	// GetFlags flags containing the direction of the CtKey.
	GetFlags() uint8

	GetTupleKey() tuple.TupleKey
}

type CtKey4Global struct {
	tuple.TupleKey4Global
}

// ToNetwork converts ports to network byte order.
//
// This is necessary to prevent callers from implicitly converting
// the CtKey4Global type here into a local key type in the nested
// TupleKey4Global field.
func (k *CtKey4Global) ToNetwork() CtKey {
	return &CtKey4Global{
		TupleKey4Global: *k.TupleKey4Global.ToNetwork().(*tuple.TupleKey4Global),
	}
}

// ToHost converts ports to host byte order.
//
// This is necessary to prevent callers from implicitly converting
// the CtKey4Global type here into a local key type in the nested
// TupleKey4Global field.
func (k *CtKey4Global) ToHost() CtKey {
	return &CtKey4Global{
		TupleKey4Global: *k.TupleKey4Global.ToHost().(*tuple.TupleKey4Global),
	}
}

// GetFlags returns the tuple's flags.
func (k *CtKey4Global) GetFlags() uint8 {
	return k.Flags
}

func (k *CtKey4Global) String() string {
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

func (k *CtKey4Global) New() bpf.MapKey { return &CtKey4Global{} }

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k *CtKey4Global) Dump(sb *strings.Builder, reverse bool) bool {
	if k.NextHeader == 0 {
		return false
	}

	sb.WriteString(k.NextHeader.String())

	addrSource := k.SourceAddr
	addrDest := k.DestAddr
	// Addresses swapped, see issue #5848
	if reverse {
		addrSource, addrDest = addrDest, addrSource
	}

	var buf [32]byte
	if k.Flags&TUPLE_F_SERVICE != 0 {
		sb.WriteString(" SVC ")
		sb.Write(k.SourceAddr.AppendTo(buf[:0]))
		sb.WriteByte(':')
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.DestPort), 10))
		sb.WriteString(" -> ")
		sb.Write(k.DestAddr.AppendTo(buf[:0]))
		sb.WriteByte(':')
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.SourcePort), 10))
		sb.WriteByte(' ')
	} else if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(" IN ")
		sb.Write(addrSource.AppendTo(buf[:0]))
		sb.WriteByte(':')
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.SourcePort), 10))
		sb.WriteString(" -> ")
		sb.Write(addrDest.AppendTo(buf[:0]))
		sb.WriteByte(':')
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.DestPort), 10))
		sb.WriteByte(' ')
	} else {
		sb.WriteString(" OUT ")
		sb.Write(addrSource.AppendTo(buf[:0]))
		sb.WriteByte(':')
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.SourcePort), 10))
		sb.WriteString(" -> ")
		sb.Write(addrDest.AppendTo(buf[:0]))
		sb.WriteByte(':')
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.DestPort), 10))
		sb.WriteByte(' ')
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		sb.WriteString("related ")
	}

	return true
}

func (k *CtKey4Global) GetTupleKey() tuple.TupleKey {
	return &k.TupleKey4Global
}

// CtKey6Global is needed to provide CtEntry type to Lookup values
type CtKey6Global struct {
	tuple.TupleKey6Global
}

const SizeofCtKey6Global = int(unsafe.Sizeof(CtKey6Global{}))

// ToNetwork converts ports to network byte order.
//
// This is necessary to prevent callers from implicitly converting
// the CtKey6Global type here into a local key type in the nested
// TupleKey6Global field.
func (k *CtKey6Global) ToNetwork() CtKey {
	return &CtKey6Global{
		TupleKey6Global: *k.TupleKey6Global.ToNetwork().(*tuple.TupleKey6Global),
	}
}

// ToHost converts ports to host byte order.
//
// This is necessary to prevent callers from implicitly converting
// the CtKey6Global type here into a local key type in the nested
// TupleKey6Global field.
func (k *CtKey6Global) ToHost() CtKey {
	return &CtKey6Global{
		TupleKey6Global: *k.TupleKey6Global.ToHost().(*tuple.TupleKey6Global),
	}
}

// GetFlags returns the tuple's flags.
func (k *CtKey6Global) GetFlags() uint8 {
	return k.Flags
}

func (k *CtKey6Global) String() string {
	b := make([]byte, 0, 96)
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

func (k *CtKey6Global) New() bpf.MapKey { return &CtKey6Global{} }

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k *CtKey6Global) Dump(sb *strings.Builder, reverse bool) bool {
	if k.NextHeader == 0 {
		return false
	}

	sb.WriteString(k.NextHeader.String())

	addrSource := k.SourceAddr
	addrDest := k.DestAddr
	// Addresses swapped, see issue #5848
	if reverse {
		addrSource, addrDest = addrDest, addrSource
	}

	var buf [48]byte
	if k.Flags&TUPLE_F_SERVICE != 0 {
		sb.WriteString(" SVC [")
		sb.Write(k.SourceAddr.AppendTo(buf[:0]))
		sb.WriteString("]:")
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.DestPort), 10))
		sb.WriteString(" -> [")
		sb.Write(k.DestAddr.AppendTo(buf[:0]))
		sb.WriteString("]:")
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.SourcePort), 10))
		sb.WriteByte(' ')
	} else if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(" IN [")
		sb.Write(addrSource.AppendTo(buf[:0]))
		sb.WriteString("]:")
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.SourcePort), 10))
		sb.WriteString(" -> [")
		sb.Write(addrDest.AppendTo(buf[:0]))
		sb.WriteString("]:")
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.DestPort), 10))
		sb.WriteByte(' ')
	} else {
		sb.WriteString(" OUT [")
		sb.Write(addrSource.AppendTo(buf[:0]))
		sb.WriteString("]:")
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.SourcePort), 10))
		sb.WriteString(" -> [")
		sb.Write(addrDest.AppendTo(buf[:0]))
		sb.WriteString("]:")
		sb.Write(strconv.AppendUint(buf[:0], uint64(k.DestPort), 10))
		sb.WriteByte(' ')
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		sb.WriteString("related ")
	}

	return true
}

func (k *CtKey6Global) GetTupleKey() tuple.TupleKey {
	return &k.TupleKey6Global
}

// CtEntry represents an entry in the connection tracking table.
type CtEntry struct {
	Union0   [2]uint64 `align:"$union0"`
	Packets  uint64    `align:"packets"`
	Bytes    uint64    `align:"bytes"`
	Lifetime uint32    `align:"lifetime"`
	Flags    uint16    `align:"rx_closing"`
	// RevNAT is in network byte order
	RevNAT uint16 `align:"rev_nat_index"`
	// NatPort is in network byte order
	NatPort          uint16 `align:"nat_port"`
	TxFlagsSeen      uint8  `align:"tx_flags_seen"`
	RxFlagsSeen      uint8  `align:"rx_flags_seen"`
	SourceSecurityID uint32 `align:"src_sec_id"`
	LastTxReport     uint32 `align:"last_tx_report"`
	LastRxReport     uint32 `align:"last_rx_report"`
}

const SizeofCtEntry = int(unsafe.Sizeof(CtEntry{}))

const (
	RxClosing = 1 << iota
	TxClosing
	Nat64
	LBLoopback
	SeenNonSyn
	NodePort
	ProxyRedirect
	DSRInternal
	FromL7LB
	Reserved1
	FromTunnel
	MaxFlags
)

func (c *CtEntry) isDsrInternalEntry() bool {
	return c.Flags&DSRInternal != 0
}

func appendHex2(b []byte, v uint8) []byte {
	const hex = "0123456789abcdef"
	return append(b, hex[(v>>4)&0xf], hex[v&0xf])
}

func (c *CtEntry) appendFlags(b []byte) []byte {
	b = append(b, "Flags=0x"...)
	var buf [4]byte
	const hex = "0123456789abcdef"
	buf[0] = hex[(c.Flags>>12)&0xf]
	buf[1] = hex[(c.Flags>>8)&0xf]
	buf[2] = hex[(c.Flags>>4)&0xf]
	buf[3] = hex[c.Flags&0xf]
	b = append(b, buf[:]...)
	b = append(b, " [ "...)

	if (c.Flags & RxClosing) != 0 {
		b = append(b, "RxClosing "...)
	}
	if (c.Flags & TxClosing) != 0 {
		b = append(b, "TxClosing "...)
	}
	if (c.Flags & Nat64) != 0 {
		b = append(b, "Nat64 "...)
	}
	if (c.Flags & LBLoopback) != 0 {
		b = append(b, "LBLoopback "...)
	}
	if (c.Flags & SeenNonSyn) != 0 {
		b = append(b, "SeenNonSyn "...)
	}
	if (c.Flags & NodePort) != 0 {
		b = append(b, "NodePort "...)
	}
	if (c.Flags & ProxyRedirect) != 0 {
		b = append(b, "ProxyRedirect "...)
	}
	if (c.Flags & DSRInternal) != 0 {
		b = append(b, "DSRInternal "...)
	}
	if (c.Flags & FromL7LB) != 0 {
		b = append(b, "FromL7LB "...)
	}
	if (c.Flags & FromTunnel) != 0 {
		b = append(b, "FromTunnel "...)
	}

	unknownFlags := c.Flags
	unknownFlags &^= MaxFlags - 1
	if unknownFlags != 0 {
		b = append(b, "Unknown=0x"...)
		buf[0] = hex[(unknownFlags>>12)&0xf]
		buf[1] = hex[(unknownFlags>>8)&0xf]
		buf[2] = hex[(unknownFlags>>4)&0xf]
		buf[3] = hex[unknownFlags&0xf]
		b = append(b, buf[:]...)
		b = append(b, ' ')
	}
	b = append(b, ']')
	return b
}

func (c *CtEntry) flagsString() string {
	b := make([]byte, 0, 64)
	return string(c.appendFlags(b))
}

func (c *CtEntry) StringWithTimeDiff(toRemSecs func(uint32) string) string {
	b := make([]byte, 0, 256)
	b = append(b, "expires="...)
	b = strconv.AppendUint(b, uint64(c.Lifetime), 10)
	if toRemSecs != nil {
		b = append(b, " ("...)
		b = append(b, toRemSecs(c.Lifetime)...)
		b = append(b, ')')
	}
	b = append(b, " Packets="...)
	b = strconv.AppendUint(b, c.Packets, 10)
	b = append(b, " Bytes="...)
	b = strconv.AppendUint(b, c.Bytes, 10)
	b = append(b, " RxFlagsSeen=0x"...)
	b = appendHex2(b, c.RxFlagsSeen)
	b = append(b, " LastRxReport="...)
	b = strconv.AppendUint(b, uint64(c.LastRxReport), 10)
	b = append(b, " TxFlagsSeen=0x"...)
	b = appendHex2(b, c.TxFlagsSeen)
	b = append(b, " LastTxReport="...)
	b = strconv.AppendUint(b, uint64(c.LastTxReport), 10)
	b = append(b, ' ')
	b = c.appendFlags(b)
	b = append(b, " RevNAT="...)
	b = strconv.AppendUint(b, uint64(byteorder.NetworkToHost16(c.RevNAT)), 10)
	b = append(b, " SourceSecurityID="...)
	b = strconv.AppendUint(b, uint64(c.SourceSecurityID), 10)
	b = append(b, " BackendID="...)
	b = strconv.AppendUint(b, c.Union0[1], 10)
	b = append(b, " NatPort="...)
	b = strconv.AppendUint(b, uint64(byteorder.NetworkToHost16(c.NatPort)), 10)
	b = append(b, " \n"...)
	return string(b)
}

// String returns the readable format
func (c *CtEntry) String() string {
	return c.StringWithTimeDiff(nil)
}

func (c *CtEntry) New() bpf.MapValue { return &CtEntry{} }

type GCRunner interface {
	// Run runs the oneshot connection tracking garbage collection.
	Run(filter GCFilter) (int, error)

	// Observe4 allows external consumers to observe ongoing GC iterations over CT maps for IPv4 entries.
	Observe4() stream.Observable[GCEvent]

	// Observe6 allows external consumers to observe ongoing GC iterations over CT maps for IPv6 entries.
	Observe6() stream.Observable[GCEvent]
}

type fakeCTMapGC struct{}

func NewFakeGCRunner() GCRunner { return fakeCTMapGC{} }

func (g fakeCTMapGC) Run(filter GCFilter) (int, error) {
	return 0, nil
}

func (g fakeCTMapGC) Observe4() stream.Observable[GCEvent] {
	return stream.FuncObservable[GCEvent](func(ctx context.Context, next func(event GCEvent), complete func(err error)) {})
}

func (g fakeCTMapGC) Observe6() stream.Observable[GCEvent] {
	return stream.FuncObservable[GCEvent](func(ctx context.Context, next func(event GCEvent), complete func(err error)) {})
}
