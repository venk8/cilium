// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"strconv"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
)

// NatEntry4 represents an IPv4 entry in the NAT table.
type NatEntry4 struct {
	Created uint64     `align:"created"`
	NeedsCT uint64     `align:"needs_ct"`
	Pad1    uint64     `align:"pad1"`
	Pad2    uint64     `align:"pad2"`
	Addr    types.IPv4 `align:"to_saddr"`
	Port    uint16     `align:"to_sport"`
	_       uint16
}

// String returns the readable format.
func (n *NatEntry4) String() string {
	b := make([]byte, 0, 64)
	b = append(b, "Addr="...)
	b = append(b, n.Addr.String()...)
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
func (n *NatEntry4) Dump(key NatKey, toDeltaSecs func(uint64) string) string {
	var which string
	if key.GetFlags()&tuple.TUPLE_F_IN != 0 {
		which = "DST "
	} else {
		which = "SRC "
	}
	b := make([]byte, 0, 64)
	b = append(b, "XLATE_"...)
	b = append(b, which...)
	b = append(b, n.Addr.String()...)
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(n.Port), 10)
	b = append(b, " Created="...)
	b = append(b, toDeltaSecs(n.Created)...)
	b = append(b, " NeedsCT="...)
	b = strconv.AppendUint(b, n.NeedsCT, 10)
	b = append(b, '\n')
	return string(b)
}

// ToHost converts NatEntry4 ports to host byte order.
func (n *NatEntry4) ToHost() NatEntry {
	x := *n
	x.Port = byteorder.NetworkToHost16(n.Port)
	return &x
}

func (n *NatEntry4) New() bpf.MapValue { return &NatEntry4{} }
