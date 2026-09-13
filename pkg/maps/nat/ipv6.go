// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"strconv"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
)

// NatEntry6 represents an IPv6 entry in the NAT table.
type NatEntry6 struct {
	Created uint64     `align:"created"`
	NeedsCT uint64     `align:"needs_ct"`
	Pad1    uint64     `align:"pad1"`
	Pad2    uint64     `align:"pad2"`
	Addr    types.IPv6 `align:"to_saddr"`
	Port    uint16     `align:"to_sport"`
	_       [6]byte
}

// SizeofNatEntry6 is the size of the NatEntry6 type in bytes.
const SizeofNatEntry6 = int(unsafe.Sizeof(NatEntry6{}))

// String returns the readable format.
func (n *NatEntry6) String() string {
	b := make([]byte, 0, 128)
	b = append(b, "Addr="...)
	b = n.Addr.AppendTo(b)
	b = append(b, " Port="...)
	b = strconv.AppendUint(b, uint64(n.Port), 10)
	b = append(b, " Created="...)
	b = strconv.AppendUint(b, n.Created, 10)
	b = append(b, " NeedsCT="...)
	b = strconv.AppendUint(b, n.NeedsCT, 10)
	b = append(b, '\n')
	return string(b)
}

// Dump dumps NAT entry to string.
func (n *NatEntry6) Dump(key NatKey, toDeltaSecs func(uint64) string) string {
	var which string
	if key.GetFlags()&tuple.TUPLE_F_IN != 0 {
		which = "DST ["
	} else {
		which = "SRC ["
	}
	b := make([]byte, 0, 128)
	b = append(b, "XLATE_"...)
	b = append(b, which...)
	b = n.Addr.AppendTo(b)
	b = append(b, "]:"...)
	b = strconv.AppendUint(b, uint64(n.Port), 10)
	b = append(b, " Created="...)
	b = append(b, toDeltaSecs(n.Created)...)
	b = append(b, " NeedsCT="...)
	b = strconv.AppendUint(b, n.NeedsCT, 10)
	b = append(b, '\n')
	return string(b)
}

// ToHost converts NatEntry4 ports to host byte order.
func (n *NatEntry6) ToHost() NatEntry {
	x := *n
	x.Port = byteorder.NetworkToHost16(n.Port)
	return &x
}

func (n *NatEntry6) New() bpf.MapValue { return &NatEntry6{} }
