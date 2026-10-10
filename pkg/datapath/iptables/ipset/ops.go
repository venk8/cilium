// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

func newOps(logger *slog.Logger, ipset *ipset, cfg config) *ops {
	return &ops{
		enabled: cfg.NodeIPSetNeeded,
		ipset:   ipset,
	}
}

type ops struct {
	enabled bool
	doPrune atomic.Bool
	ipset   *ipset
}

// UpdateBatch implements reconciler.BatchOperations.
func (ops *ops) UpdateBatch(ctx context.Context, txn statedb.ReadTxn, batch []reconciler.BatchEntry[*tables.IPSetEntry]) {
	if !ops.enabled {
		return
	}

	err := ops.ipset.restoreBatch(ctx, "add", batch)
	if err != nil {
		// Fail the whole batch.
		for i := range batch {
			batch[i].Result = err
		}
	}
}

// DeleteBatch implements reconciler.BatchOperations.
func (ops *ops) DeleteBatch(ctx context.Context, txn statedb.ReadTxn, batch []reconciler.BatchEntry[*tables.IPSetEntry]) {
	if !ops.enabled {
		return
	}

	err := ops.ipset.restoreBatch(ctx, "del", batch)
	if err != nil {
		// Fail the whole batch.
		for i := range batch {
			batch[i].Result = err
		}
	}
}

var _ reconciler.Operations[*tables.IPSetEntry] = &ops{}
var _ reconciler.BatchOperations[*tables.IPSetEntry] = &ops{}

func (ops *ops) Update(ctx context.Context, _ statedb.ReadTxn, _ statedb.Revision, entry *tables.IPSetEntry) error {
	if !ops.enabled {
		return nil
	}

	return ops.ipset.restoreEntry(ctx, "add", entry.Name, entry.Addr)
}

func (ops *ops) Delete(ctx context.Context, _ statedb.ReadTxn, _ statedb.Revision, entry *tables.IPSetEntry) error {
	if !ops.enabled {
		return nil
	}

	return ops.ipset.restoreEntry(ctx, "del", entry.Name, entry.Addr)
}

func (ops *ops) Prune(ctx context.Context, _ statedb.ReadTxn, objs iter.Seq2[*tables.IPSetEntry, statedb.Revision]) error {
	if !ops.enabled || !ops.doPrune.Load() {
		return nil
	}

	desiredV4Set, desiredV6Set := sets.Set[netip.Addr]{}, sets.Set[netip.Addr]{}

	for obj := range objs {
		if obj.Name == CiliumNodeIPSetV4 {
			desiredV4Set.Insert(obj.Addr)
		} else if obj.Name == CiliumNodeIPSetV6 {
			desiredV6Set.Insert(obj.Addr)
		}
	}

	return errors.Join(
		reconcile(ctx, ops.ipset, CiliumNodeIPSetV4, INetFamily, desiredV4Set),
		reconcile(ctx, ops.ipset, CiliumNodeIPSetV6, INet6Family, desiredV6Set),
	)
}

func reconcile(
	ctx context.Context,
	ipset *ipset,
	name string,
	family Family,
	desired sets.Set[netip.Addr],
) error {
	// create the IP set if it doesn't exist
	if err := ipset.create(ctx, name, string(family)); err != nil {
		return fmt.Errorf("unable to create ipset %s: %w", name, err)
	}

	curSet, err := ipset.list(ctx, name)
	if err != nil {
		return fmt.Errorf("unable to list ipset %s: %w", name, err)
	}

	toDel := curSet.Difference(desired)
	if err := ipset.restoreSet(ctx, "del", name, toDel); err != nil {
		return fmt.Errorf("unable to delete from ipset: %w", err)
	}

	toAdd := desired.Difference(curSet)
	if err := ipset.restoreSet(ctx, "add", name, toAdd); err != nil {
		return fmt.Errorf("unable to delete from ipset: %w", err)
	}
	return nil
}

func (ops *ops) enablePrune() {
	ops.doPrune.Store(true)
}
