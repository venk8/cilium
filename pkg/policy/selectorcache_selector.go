// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"slices"
	"sync"

	"github.com/hashicorp/go-hclog"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/types"
)

type CachedSelector = types.CachedSelector
type CachedSelectorSlice = types.CachedSelectorSlice
type CachedSelectionUser = types.CachedSelectionUser
type Selector = types.Selector
type Selectors = types.Selectors
type SelectorSnapshot = types.SelectorSnapshot
type SelectorRevision = types.SelectorRevision

// identitySelector is the internal type for all selectors in the
// selector cache.
//
// identitySelector represents the mapping of an EndpointSelector
// to a slice of identities. These mappings are updated via two
// different processes:
//
// 1. When policy rules are changed these are added and/or deleted
// depending on what selectors the rules contain. Cached selections of
// new identitySelectors are pre-populated from the set of currently
// known identities.
//
// 2. When reachable identities appear or disappear, either via local
// allocation (CIDRs), or via the KV-store (remote endpoints). In this
// case all existing identitySelectors are walked through and their
// cached selections are updated as necessary.
//
// In both of the above cases the set of existing identitySelectors is
// write locked.
//
// To minimize the upkeep the identity selectors are shared across
// all IdentityPolicies, so that only one copy exists for each
// identitySelector. Users of the SelectorCache take care of creating
// identitySelectors as needed by identity policies. The set of
// identitySelectors is read locked during an IdentityPolicy update so
// that the policy is always updated using a coherent set of
// cached selections.
//
// identitySelector is used as a map key, so it must not be implemented by a
// map, slice, or a func, or a runtime panic will be triggered. In all
// cases below identitySelector is being implemented by structs.
//
// identitySelector is used in the policy engine as a map key,
// so it must always be given to the user as a pointer to the actual type.
// (The public methods only expose the CachedSelector interface.)
type identitySelector struct {
	selectorCache    *SelectorCache
	source           Selector
	key              string
	id               types.SelectorId
	users            map[CachedSelectionUser]struct{}
	cachedSelections map[identity.NumericIdentity]struct{}
}

var lastSelectorId types.SelectorId

func newIdentitySelector(sc *SelectorCache, key string, source Selector) *identitySelector {
	lastSelectorId++
	return &identitySelector{
		selectorCache:    sc,
		key:              key,
		id:               lastSelectorId,
		users:            make(map[CachedSelectionUser]struct{}),
		cachedSelections: make(map[identity.NumericIdentity]struct{}),
		source:           source,
	}
}

func (i *identitySelector) MaySelectPeers() bool {
	for user := range i.users {
		if user.IsPeerSelector() {
			return true
		}
	}
	return false
}

// identitySelector implements CachedSelector
var _ CachedSelector = (*identitySelector)(nil)

// lock must be held
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
func (i *identitySelector) notifyUsers(sc *SelectorCache, added, deleted []identity.NumericIdentity, wg *sync.WaitGroup) {
	for user := range i.users {
		// pass 'f' to the user as '*fqdnSelector'
		sc.queueUserNotification(user, i, added, deleted, wg)
	}
}

// Equal is used by checker.Equals, and only considers the identity of the selector,
// ignoring the internal state!
func (i *identitySelector) Equal(b *identitySelector) bool {
	return i.key == b.key
}

//
// CachedSelector implementation (== Public API)
//
// No locking needed and selector cache must not be locked when making these calls!
// (SelectorCache.GetReadTxn() takes a read lock)
//

// GetSelections returns the set of numeric identities currently selected.
func (i *identitySelector) GetSelections() identity.NumericIdentitySlice {
	return i.GetSelectionsAt(i.selectorCache.GetSelectorSnapshot())
}

// GetSelectionsAt returns the set of numeric identities selected at the given snapshot.
func (i *identitySelector) GetSelectionsAt(selectors SelectorSnapshot) identity.NumericIdentitySlice {
	if !selectors.IsValid() || i.id == 0 {
		msg := "GetSelectionsAt: Invalid selector snapshot finds nothing"
		if i.id == 0 {
			msg = "GetSelectionsAt: Uninitialized identitySelector"
		}
		i.selectorCache.logger.Error(
			msg,
			logfields.Version, selectors,
			logfields.Stacktrace, hclog.Stacktrace(),
		)
		return identity.NumericIdentitySlice{}
	}
	return selectors.Get(i.id)
}

func (i *identitySelector) GetMetadataLabels() labels.LabelArrayList {
	list := labels.LabelArrayList{}
	// pull labels from all the current users
	for user := range i.users {
		lal := user.GetRuleLabels(i)
		list.MergeSorted(lal)
	}
	return list
}

// Selects return 'true' if the CachedSelector selects the given
// numeric identity.
func (i *identitySelector) Selects(nid identity.NumericIdentity) bool {
	if i.IsWildcard() {
		return true
	}
	nids := i.GetSelections()
	_, found := slices.BinarySearch(nids, nid)
	return found
}

// IsWildcard returns true if the endpoint selector selects all
// endpoints.
func (i *identitySelector) IsWildcard() bool {
	return i.key == wildcardSelectorKey
}

// IsNone returns true if the endpoint selector never selects anything.
func (i *identitySelector) IsNone() bool {
	return i.key == noneSelectorKey
}

// String returns the map key for this selector
func (i *identitySelector) String() string {
	return i.key
}

//
// identitySelector implementation (== internal API)
//

// lock must be held
func (i *identitySelector) addUser(user CachedSelectionUser, idNotifier identityNotifier) (added bool) {
	if _, exists := i.users[user]; exists {
		return false
	}
	i.users[user] = struct{}{}

	// register FQDN on first user
	if len(i.users) == 1 && idNotifier != nil {
		// Check if need to register with the dns proxy
		if fqdn, ok := i.source.GetFQDNSelector(); ok {
			// Make the FQDN subsystem aware of this selector
			idNotifier.RegisterFQDNSelector(*fqdn)
		}
	}

	return true
}

// locks must be held for the dnsProxy and the SelectorCache (if the selector is a FQDN selector)
func (i *identitySelector) removeUser(user CachedSelectionUser, idNotifier identityNotifier) (last bool) {
	if _, exists := i.users[user]; exists {
		delete(i.users, user)

		if len(i.users) == 0 {
			if idNotifier != nil {
				if fqdn, ok := i.source.GetFQDNSelector(); ok {
					idNotifier.UnregisterFQDNSelector(*fqdn)
				}
			}
			return true
		}
	}
	return false
}

// lock must be held
func (i *identitySelector) numUsers() int {
	return len(i.users)
}

// updateSelections updates the immutable slice representation of the
// cached selections after the cached selections have been changed.
//
// lock must be held
func (i *identitySelector) updateSelections() {
	if len(i.cachedSelections) == 0 {
		i.selectorCache.writeableSelections.Delete(i.id)
		return
	}

	ids := make(identity.NumericIdentitySlice, 0, len(i.cachedSelections))

	for nid := range i.cachedSelections {
		ids = append(ids, nid)
	}

	// Sort the numeric identities so that the map iteration order
	// does not matter. This makes testing easier, but may help
	// identifying changes easier also otherwise.
	slices.Sort(ids)

	i.selectorCache.writeableSelections.Set(i.id, ids)
}

// updateSelectionsDelta incrementally updates the immutable slice representation
// of the cached selections with the provided added and deleted identities.
//
// lock must be held
func (i *identitySelector) updateSelectionsDelta(adds, dels []identity.NumericIdentity) {
	if len(i.cachedSelections) == 0 {
		i.selectorCache.writeableSelections.Delete(i.id)
		return
	}

	oldIDs, found := i.selectorCache.writeableSelections.Get(i.id)
	if !found || len(oldIDs) == 0 {
		i.updateSelections()
		return
	}

	// Fast path: single deletion, no additions
	if len(dels) == 1 && len(adds) == 0 {
		delID := dels[0]
		if idx, exists := slices.BinarySearch(oldIDs, delID); exists {
			if len(oldIDs) == 1 {
				i.selectorCache.writeableSelections.Delete(i.id)
				return
			}
			newIDs := make(identity.NumericIdentitySlice, len(oldIDs)-1)
			copy(newIDs[:idx], oldIDs[:idx])
			copy(newIDs[idx:], oldIDs[idx+1:])
			i.selectorCache.writeableSelections.Set(i.id, newIDs)
			return
		}
		// Inconsistency or already removed; fall back to full rebuild
		i.updateSelections()
		return
	}

	// Fast path: single addition, no deletions
	if len(adds) == 1 && len(dels) == 0 {
		addID := adds[0]
		idx, exists := slices.BinarySearch(oldIDs, addID)
		if !exists {
			newIDs := make(identity.NumericIdentitySlice, len(oldIDs)+1)
			copy(newIDs[:idx], oldIDs[:idx])
			newIDs[idx] = addID
			copy(newIDs[idx+1:], oldIDs[idx:])
			i.selectorCache.writeableSelections.Set(i.id, newIDs)
			return
		}
		// Inconsistency or already present; fall back to full rebuild
		i.updateSelections()
		return
	}

	// Multi-item delta path: 3-way merge
	slices.Sort(adds)
	adds = slices.Compact(adds)
	slices.Sort(dels)
	dels = slices.Compact(dels)

	newCap := len(oldIDs) + len(adds)
	if len(dels) <= newCap {
		newCap -= len(dels)
	}
	newIDs := make(identity.NumericIdentitySlice, 0, newCap)

	iOld, iAdd, iDel := 0, 0, 0
	for iOld < len(oldIDs) || iAdd < len(adds) {
		var candidate identity.NumericIdentity
		if iAdd < len(adds) && (iOld >= len(oldIDs) || adds[iAdd] < oldIDs[iOld]) {
			candidate = adds[iAdd]
			iAdd++
		} else if iOld < len(oldIDs) && (iAdd >= len(adds) || oldIDs[iOld] < adds[iAdd]) {
			candidate = oldIDs[iOld]
			iOld++
		} else {
			candidate = adds[iAdd]
			iAdd++
			iOld++
		}

		for iDel < len(dels) && dels[iDel] < candidate {
			iDel++
		}
		if iDel < len(dels) && dels[iDel] == candidate {
			iDel++
			continue
		}

		newIDs = append(newIDs, candidate)
	}

	if len(newIDs) != len(i.cachedSelections) {
		// Parity mismatch with cachedSelections map; fall back to full rebuild
		i.updateSelections()
		return
	}

	if len(newIDs) == 0 {
		i.selectorCache.writeableSelections.Delete(i.id)
	} else {
		i.selectorCache.writeableSelections.Set(i.id, newIDs)
	}
}
