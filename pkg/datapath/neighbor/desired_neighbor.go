// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbor

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
)

type DesiredNeighbor struct {
	DesiredNeighborKey

	Status reconciler.Status
}

func (dn *DesiredNeighbor) Clone() *DesiredNeighbor {
	return &DesiredNeighbor{
		DesiredNeighborKey: dn.DesiredNeighborKey,
		Status:             dn.Status,
	}
}

func (dn *DesiredNeighbor) SetStatus(status reconciler.Status) *DesiredNeighbor {
	n := dn.Clone()
	n.Status = status
	return n
}

func (dn *DesiredNeighbor) GetStatus() reconciler.Status {
	return dn.Status
}

type DesiredNeighborKey struct {
	IP      netip.Addr
	IfIndex int
}

func (dn DesiredNeighborKey) TableKey() index.Key {
	key := make(index.Key, 20)
	binary.BigEndian.PutUint32(key[:4], uint32(dn.IfIndex))
	addrBytes := dn.IP.As16()
	copy(key[4:20], addrBytes[:])
	return key
}

func (dn DesiredNeighborKey) String() string {
	b := make([]byte, 0, 16+1+10)
	b = dn.IP.AppendTo(b)
	b = append(b, '@')
	b = strconv.AppendInt(b, int64(dn.IfIndex), 10)
	return string(b)
}

func desiredNeighborKeyFromString(s string) (index.Key, error) {
	ipStr, ifIndexStr, ok := strings.Cut(s, "@")
	if !ok {
		return nil, fmt.Errorf("invalid key format: '%s' expected {ip}@{ifindex}", s)
	}

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address: %w", err)
	}

	ifIndex, err := strconv.ParseUint(ifIndexStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid interface index: %w", err)
	}

	key := make(index.Key, 20)
	binary.BigEndian.PutUint32(key[:4], uint32(ifIndex))
	addrBytes := addr.As16()
	copy(key[4:20], addrBytes[:])
	return key, nil
}

func (dn *DesiredNeighbor) TableHeader() []string {
	return []string{
		"IP",
		"Link",
		"Status",
	}
}

func (dn *DesiredNeighbor) TableRow() []string {
	return []string{
		dn.IP.String(),
		fmt.Sprintf("%d", dn.IfIndex),
		dn.Status.Kind.String(),
	}
}

var (
	DesiredNeighborIndex = statedb.Index[*DesiredNeighbor, DesiredNeighborKey]{
		Name: "id",
		FromObject: func(d *DesiredNeighbor) index.KeySet {
			return index.NewKeySet(d.TableKey())
		},
		FromKey:    DesiredNeighborKey.TableKey,
		FromString: desiredNeighborKeyFromString,
		Unique:     true,
	}
)

func newDesiredNeighborTable(db *statedb.DB) (statedb.RWTable[*DesiredNeighbor], error) {
	return statedb.NewTable(
		db,
		"desired-neighbors",
		DesiredNeighborIndex,
	)
}
