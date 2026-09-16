// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

// Stats provides a implementation of performing nat map stats
// counting.
type Stats struct {
	logger *slog.Logger

	metrics natMetrics

	db    *statedb.DB
	table statedb.RWTable[NatMapStats]

	maxPorts int
	config   Config
	natMap4  nat.NatMap4
	natMap6  nat.NatMap6

	observable4 stream.Observable[TupleCountIterator]
	next4       func(TupleCountIterator)
	complete4   func(error)

	observable6 stream.Observable[TupleCountIterator]
	next6       func(TupleCountIterator)
	complete6   func(error)
}

// Observable4 returns the state iteration observable for ipv4 nat.
func (s *Stats) Observable4() stream.Observable[TupleCountIterator] {
	return s.observable4
}

// Observable6 returns the state iteration observable for ipv6 nat.
func (s *Stats) Observable6() stream.Observable[TupleCountIterator] {
	return s.observable6
}

// TupleCountIterator is a k/v iterator type that allows for opaquely
// accessing a set of snat tuple source port counts.
// This is used by the exported Observable{4,6} streams to allow for
// external consumers to iterate over the current set of nat map stats
// following a countNat operation.
type TupleCountIterator iter.Seq2[SNATTupleAccessor, uint16]

// NatMapStats is a nat-map table entry key/value. This
// contains a count of connection 3-tuple utilization.
type NatMapStats struct {
	Type       string
	EgressIP   string
	EndpointIP string
	RemotePort uint16
	Proto      string
	Count      int
}

func (s NatMapStats) Key() index.Key {
	k := make(index.Key, 0, len(s.Type)+len(s.EgressIP)+len(s.EndpointIP)+5)
	k = append(k, s.Type...)
	k = append(k, ' ')
	k = append(k, s.EgressIP...)
	k = append(k, ' ')
	k = append(k, s.EndpointIP...)
	k = append(k, ':')
	return binary.BigEndian.AppendUint16(k, s.RemotePort)
}

func (s NatMapStats) addrs() (string, string) {
	if s.Type == nat.IPv6.String() {
		return "[" + s.EgressIP + "]", "[" + s.EndpointIP + "]"
	}
	return s.EgressIP, s.EndpointIP
}

func (NatMapStats) TableHeader() []string {
	return []string{"IPFamily", "Proto", "EgressIP", "RemoteAddr", "Count"}
}

func (s NatMapStats) TableRow() []string {
	var raddr string
	eip, rip := s.addrs()
	if s.RemotePort == 0 {
		raddr = rip
	} else {
		raddr = fmt.Sprintf("%s:%d", rip, s.RemotePort)
	}
	return []string{s.Type, s.Proto, eip, raddr, strconv.Itoa(s.Count)}
}

type params struct {
	cell.In

	Logger *slog.Logger

	Lifecycle cell.Lifecycle
	DB        *statedb.DB
	Table     statedb.RWTable[NatMapStats]
	NatMap4   nat.NatMap4
	NatMap6   nat.NatMap6
	Jobs      job.Group
	Metrics   natMetrics
	Config    Config
	LBConfig  loadbalancer.Config
	Health    cell.Health
}

const nodePortMaxNAT = 65535

func newStats(params params) (*Stats, error) {
	if params.Config.NATMapStatInterval == 0 {
		return nil, nil
	}

	if params.Config.NatMapStatKStoredEntries > maxNatMapStatKStoredEntries ||
		params.Config.NatMapStatKStoredEntries < minNatMapStatKStoredEntries {
		return nil, fmt.Errorf("nat-stats config: %q must be between [%d, %d]",
			natMapStatsEntriesName, minNatMapStatKStoredEntries, maxNatMapStatKStoredEntries)
	}

	// number of available source-ports is ephemeral range subtracting those
	// used by node-ports.
	maxAvailPorts := nodePortMaxNAT - (params.LBConfig.NodePortMax + 1)
	m := &Stats{
		logger:   params.Logger,
		metrics:  params.Metrics,
		config:   params.Config,
		maxPorts: int(maxAvailPorts),
		db:       params.DB,
		table:    params.Table,
	}

	m.observable4, m.next4, m.complete4 =
		stream.Multicast[TupleCountIterator]()
	m.observable6, m.next6, m.complete6 =
		stream.Multicast[TupleCountIterator]()

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			m.natMap4 = params.NatMap4
			m.natMap6 = params.NatMap6
			if m.natMap4 == nil && m.natMap6 == nil {
				return nil
			}

			tr := job.NewTrigger()
			params.Jobs.Add(job.Timer("nat-stats", m.countNat, params.Config.NATMapStatInterval,
				job.WithTrigger(tr)))
			// Wait a couple seconds, and then trigger the initial count.
			// This is to give time for init time CT/NAT gc scanning to complete
			// to avoid NAT map GC timeouts at startup.
			go func() {
				<-time.After(5 * time.Second)
				tr.Trigger()
			}()
			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			m.complete4(nil)
			m.complete6(nil)
			return nil
		},
	})
	return m, nil
}

func upsertStat[T SNATTupleAccessor](m *Stats, topk *topk[T], family nat.IPFamily) error {
	tx := m.db.WriteTxn(m.table)
	defer tx.Abort()

	var errs error
	for entry := range m.table.All(tx) {
		if entry.Type == family.String() {
			_, _, err := m.table.Delete(tx, entry)
			errs = errors.Join(errs, err)
		}
	}

	topk.popForEach(func(key T, count, ith int) {
		if ith == 1 {
			m.metrics.updateLocalPorts(family, count, m.maxPorts)
		}
		endpointIP, rport := key.GetEndpointAddr()
		egressIP, _ := key.GetEgressAddr()
		proto := key.GetProto()
		_, _, err := m.table.Insert(tx, NatMapStats{
			Type:       family.String(),
			EgressIP:   egressIP.String(),
			EndpointIP: endpointIP.String(),
			RemotePort: rport,
			Proto:      proto.String(),
			Count:      count,
		})
		if err != nil {
			errs = errors.Join(errs, err)
		}
	})
	if errs != nil {
		return fmt.Errorf("failures occurred updating stats table, transaction will not be committed: %w", errs)
	}
	tx.Commit()
	return nil
}

func flagsIsIn(flags uint8) bool {
	return flags&tuple.TUPLE_F_IN == tuple.TUPLE_F_IN
}

func (m *Stats) countNat(ctx context.Context) error {
	var errs error
	if m.natMap4 != nil {
		tupleToPortCount := make(map[SNATTuple4]uint16, 128)
		_, err := m.natMap4.DumpBatch4(func(k *tuple.TupleKey4, _ *nat.NatEntry4) {
			if flagsIsIn(k.Flags) &&
				(k.NextHeader == u8proto.TCP || k.NextHeader == u8proto.ICMP ||
					k.NextHeader == u8proto.UDP) {
				key := *k
				key.SourcePort = byteorder.NetworkToHost16(k.SourcePort)
				key.DestPort = 0
				tupleToPortCount[SNATTuple4(key)]++
			}
		})

		if err != nil {
			m.logger.Error("failed to count ipv4 nat map entries, "+
				"this may result in out of date nat-stats data and nat_endpoint_ metrics",
				logfields.Error, err,
			)
			errs = errors.Join(errs, err)
		} else {
			m.next4(toIter(tupleToPortCount))
			topk := newTopK[SNATTuple4](m.config.NatMapStatKStoredEntries)
			for tupleKey, bucket := range tupleToPortCount {
				topk.Push(tupleKey, int(bucket))
			}
			errs = errors.Join(errs, upsertStat(m, topk, nat.IPv4))
		}

	}
	if m.natMap6 != nil {
		tupleToPortCount := make(map[SNATTuple6]uint16, 128)
		_, err := m.natMap6.DumpBatch6(func(k *tuple.TupleKey6, _ *nat.NatEntry6) {
			if flagsIsIn(k.Flags) &&
				(k.NextHeader == u8proto.TCP || k.NextHeader == u8proto.ICMPv6 ||
					k.NextHeader == u8proto.UDP) {
				key := *k
				key.SourcePort = byteorder.NetworkToHost16(k.SourcePort)
				key.DestPort = 0
				tupleToPortCount[SNATTuple6(key)]++
			}
		})

		if err != nil {
			m.logger.Error("failed to count ipv6 nat map entries, "+
				"this may result in out of date nat-stats data and nat_endpoint_ metrics",
				logfields.Error, err,
			)
			errs = errors.Join(errs, err)
		} else {
			m.next6(toIter(tupleToPortCount))
			topk := newTopK[SNATTuple6](m.config.NatMapStatKStoredEntries)
			for tupleKey, bucket := range tupleToPortCount {
				topk.Push(tupleKey, int(bucket))
			}
			errs = errors.Join(errs, upsertStat(m, topk, nat.IPv6))
		}
	}
	return errs
}

type tupleBucket[T any] struct {
	key   T
	count int
}

type topk[T SNATTupleAccessor] struct {
	mq []tupleBucket[T]
	k  int
}

func newTopK[T SNATTupleAccessor](k int) *topk[T] {
	if k < 0 {
		k = 0
	}
	return &topk[T]{
		mq: make([]tupleBucket[T], 0, k),
		k:  k,
	}
}

func (t *topk[T]) Push(key T, count int) {
	if t.k <= 0 {
		return
	}
	if len(t.mq) < t.k {
		t.mq = append(t.mq, tupleBucket[T]{key: key, count: count})
		t.siftUp(len(t.mq) - 1)
		return
	}
	if count <= t.mq[0].count {
		return
	}
	t.mq[0] = tupleBucket[T]{key: key, count: count}
	t.siftDown(0)
}

func (t *topk[T]) popForEach(fn func(key T, count, ith int)) {
	initialSize := len(t.mq)
	for i := range initialSize {
		min := t.mq[0]
		lastIdx := len(t.mq) - 1
		t.mq[0] = t.mq[lastIdx]
		t.mq = t.mq[:lastIdx]
		t.siftDown(0)
		fn(min.key, min.count, initialSize-i)
	}
}

func (t *topk[T]) siftUp(i int) {
	for i > 0 {
		p := (i - 1) / 2
		if t.mq[i].count >= t.mq[p].count {
			break
		}
		t.mq[i], t.mq[p] = t.mq[p], t.mq[i]
		i = p
	}
}

func (t *topk[T]) siftDown(i int) {
	n := len(t.mq)
	for {
		left := 2*i + 1
		if left >= n {
			break
		}
		smallest := left
		if right := left + 1; right < n && t.mq[right].count < t.mq[left].count {
			smallest = right
		}
		if t.mq[i].count <= t.mq[smallest].count {
			break
		}
		t.mq[i], t.mq[smallest] = t.mq[smallest], t.mq[i]
		i = smallest
	}
}
