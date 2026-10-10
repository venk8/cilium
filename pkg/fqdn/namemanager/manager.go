// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"context"
	"hash/fnv"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

type selectorEntry struct {
	sel      api.FQDNSelector
	regex    *regexp.Regexp       // nil for exact match selectors, compiled regex for pattern selectors
	label    labels.Label         // precomputed sel.IdentityLabel()
	labels   labels.Labels        // precomputed 1-element labels.Labels{label.Key: label}
	metadata []ipcache.IPMetadata // precomputed []ipcache.IPMetadata{labels}
}

type exactEntry struct {
	entries  []selectorEntry
	labels   labels.Labels           // precomputed merged labels for this exact domain (exact + matching pattern selectors)
	metadata []ipcache.IPMetadata    // precomputed []ipcache.IPMetadata{labels}
	resource ipcacheTypes.ResourceID // precomputed ipcacheResource(canon)
}

type suffixEntry struct {
	entries  []selectorEntry
	labels   labels.Labels        // precomputed merged labels for this wildcard suffix
	metadata []ipcache.IPMetadata // precomputed []ipcache.IPMetadata{labels}
}

// The implementation of the NameManager interface.
type manager struct {
	logger *slog.Logger

	lock.RWMutex

	// params is a copy from when this instance was initialized.
	// It is read-only once set
	params ManagerParams

	// allSelectors contains all FQDNSelectors which are present in all policy. We
	// use these selectors to map selectors --> IPs.
	allSelectors map[api.FQDNSelector]*regexp.Regexp

	// exactSelectors contains exact match selectors (MatchName != "") keyed by canonical FQDN.
	exactSelectors map[string]*exactEntry

	// suffixSelectors contains single-label wildcard selectors (*.domain) keyed by canonical suffix (domain.).
	suffixSelectors map[string]*suffixEntry

	// generalPatternSelectors contains general regex/wildcard match selectors (e.g. foo.*.bar, **).
	generalPatternSelectors []selectorEntry

	cache *fqdn.DNSCache

	bootstrapCompleted bool

	// list of locks used as coordination points for name updates
	// see LockName() for details.
	nameLocks []*lock.Mutex

	// selectorChanges is a stream of added and removed selectors
	selectorChanges chan selectorChange
	// Any pre-allocated identities for selectors -- used for possible release.
	selectorIDs map[api.FQDNSelector][]identity.NumericIdentity
}

type selectorChange struct {
	added bool
	sel   api.FQDNSelector
}

// New creates an initialized NameManager.
func New(params ManagerParams) *manager {
	cache := fqdn.NewDNSCache(params.Config.MinTTL)
	// Disable cleanup tracking on the default DNS cache. This cache simply
	// tracks which api.FQDNSelector are present in policy which apply to
	// locally running endpoints.
	cache.DisableCleanupTrack()

	n := &manager{
		logger:          params.Logger,
		params:          params,
		allSelectors:    make(map[api.FQDNSelector]*regexp.Regexp),
		exactSelectors:  make(map[string]*exactEntry),
		suffixSelectors: make(map[string]*suffixEntry),
		selectorIDs:     make(map[api.FQDNSelector][]identity.NumericIdentity),
		cache:           cache,
		nameLocks:       make([]*lock.Mutex, params.Config.DNSProxyLockCount),
	}

	for i := range n.nameLocks {
		n.nameLocks[i] = &lock.Mutex{}
	}

	// Break Hive import loop -- pass the NameManager back to the SelectorCache.
	// (optional for tests)
	if params.PolicyRepo != nil {
		params.PolicyRepo.GetSelectorCache().SetLocalIdentityNotifier(n)
	}

	// Set up jobs:
	// - gc
	// - bootstrap
	// - preallocator
	// (optional for tests)
	if params.JobGroup != nil {
		params.JobGroup.Add(job.OneShot(
			"wait-for-endpoint-restore",
			func(ctx context.Context, h cell.Health) error {
				h.OK("Waiting for endpoint restoration")
				err := n.waitForEndpointRestore(ctx)
				if err != nil {
					h.Stopped("Waiting for endpoint restoration failed: " + err.Error())
					return err
				}
				h.OK("OK")

				params.JobGroup.Add(job.Timer(
					dnsGCJobName,
					n.doGC,
					DNSGCJobInterval,
				))

				return nil
			},
		))

		// Start the asynchronous prefix allocator
		// (optional for tests)
		if params.Allocator != nil && params.Config.ToFQDNsPreAllocate {
			n.selectorChanges = make(chan selectorChange, 2048)
			params.JobGroup.Add(job.Observer(
				"preallocate",
				n.processSelectorChanges,
				stream.FromChannel(n.selectorChanges)))
		}
	}

	return n
}

func isSingleWildcardPrefix(pattern string) (suffix string, ok bool) {
	pattern = strings.TrimSpace(pattern)
	if strings.HasPrefix(pattern, "*.") && strings.Count(pattern, "*") == 1 {
		trimmed := strings.TrimPrefix(pattern, "*.")
		if trimmed != "" {
			return prepareMatchName(trimmed), true
		}
	}
	return "", false
}

// RegisterFQDNSelector exposes this FQDNSelector so that the identity labels
// of IPs contained in a DNS response that matches said selector can be
// associated with that selector.
// This function also evaluates if any DNS names in the cache are matched by
// this new selector and updates the labels for those DNS names accordingly.
func (n *manager) RegisterFQDNSelector(selector api.FQDNSelector) (ipcacheRevision uint64) {
	n.Lock()
	defer n.Unlock()

	_, exists := n.allSelectors[selector]
	if exists {
		n.logger.Warn("FQDNSelector was already registered for updates.",
			logfields.FQDNSelector, selector,
		)
	} else {
		// This error should never occur since the FQDNSelector has already been
		// validated, but account for it for good measure.
		regex, err := selector.ToRegex()
		if err != nil {
			n.logger.Error("FQDNSelector did not compile to valid regex",
				logfields.Error, err,
				logfields.FQDNSelector, selector,
			)
			return
		}

		n.allSelectors[selector] = regex
		if metrics.FQDNSelectors.IsEnabled() {
			metrics.FQDNSelectors.Set(float64(len(n.allSelectors)))
		}

		label := selector.IdentityLabel()
		singleLabels := labels.Labels{label.Key: label}
		singleMetadata := []ipcache.IPMetadata{singleLabels}

		if selector.MatchName != "" {
			canon := prepareMatchName(selector.MatchName)
			entry, exists := n.exactSelectors[canon]
			if !exists {
				entry = &exactEntry{
					labels:   make(labels.Labels),
					resource: ipcacheResource(canon),
				}
				n.exactSelectors[canon] = entry
				// Incorporate any existing suffix selectors matching this exact domain
				if dot := strings.IndexByte(canon, '.'); dot > 0 {
					if sEntry, found := n.suffixSelectors[canon[dot+1:]]; found {
						for k, v := range sEntry.labels {
							entry.labels[k] = v
						}
					}
				}
				// Incorporate any existing general pattern selectors matching this exact domain
				for _, p := range n.generalPatternSelectors {
					if p.regex.MatchString(canon) {
						entry.labels[p.label.Key] = p.label
					}
				}
			}
			entry.entries = append(entry.entries, selectorEntry{
				sel:      selector,
				label:    label,
				labels:   singleLabels,
				metadata: singleMetadata,
			})
			entry.labels[label.Key] = label
			entry.metadata = []ipcache.IPMetadata{entry.labels}
		}
		if selector.MatchPattern != "" {
			if suffix, ok := isSingleWildcardPrefix(selector.MatchPattern); ok {
				sEntry, exists := n.suffixSelectors[suffix]
				if !exists {
					sEntry = &suffixEntry{
						labels: make(labels.Labels),
					}
					n.suffixSelectors[suffix] = sEntry
				}
				sEntry.entries = append(sEntry.entries, selectorEntry{
					sel:      selector,
					regex:    regex,
					label:    label,
					labels:   singleLabels,
					metadata: singleMetadata,
				})
				sEntry.labels[label.Key] = label
				sEntry.metadata = []ipcache.IPMetadata{sEntry.labels}
				// Update any existing exactSelectors matching this new suffix
				for canon, e := range n.exactSelectors {
					if dot := strings.IndexByte(canon, '.'); dot > 0 && canon[dot+1:] == suffix {
						e.labels[label.Key] = label
						e.metadata = []ipcache.IPMetadata{e.labels}
					}
				}
			} else {
				pEntry := selectorEntry{
					sel:      selector,
					regex:    regex,
					label:    label,
					labels:   singleLabels,
					metadata: singleMetadata,
				}
				n.generalPatternSelectors = append(n.generalPatternSelectors, pEntry)
				// Update any existing exactSelectors matching this new pattern
				for canon, e := range n.exactSelectors {
					if regex.MatchString(canon) {
						e.labels[label.Key] = label
						e.metadata = []ipcache.IPMetadata{e.labels}
					}
				}
			}
		}

		if n.selectorChanges != nil {
			select {
			case n.selectorChanges <- selectorChange{sel: selector, added: true}:
			default:
				// It is not a correctness issue if pre-allocation fails; it just
				// means the first allocation will happen on DNS request. Even if a
				// deletion is enqueued, we will have not recorded any allocated IDs
				// so there is no risk of imbalanced references.
				n.logger.Warn("failed to queue selector for preallocation")
			}
		}
	}

	// The newly added FQDN selector could match DNS Names in the cache. If
	// that is the case, we want to update the IPCache metadata for all
	// associated IPs
	regex := n.allSelectors[selector]
	selectedNamesAndIPs := n.mapSelectorsToNamesLocked(selector, regex)
	if len(selectedNamesAndIPs) == 0 {
		return 0
	}
	return n.updateMetadata(n.deriveLabelsForNames(selectedNamesAndIPs))
}

func (n *manager) rebuildExactEntryLabels(canon string, e *exactEntry) {
	e.labels = make(labels.Labels, len(e.entries))
	for _, entry := range e.entries {
		e.labels[entry.label.Key] = entry.label
	}
	if dot := strings.IndexByte(canon, '.'); dot > 0 {
		if sEntry, found := n.suffixSelectors[canon[dot+1:]]; found {
			for k, v := range sEntry.labels {
				e.labels[k] = v
			}
		}
	}
	for _, p := range n.generalPatternSelectors {
		if p.regex.MatchString(canon) {
			e.labels[p.label.Key] = p.label
		}
	}
	e.metadata = []ipcache.IPMetadata{e.labels}
}

// UnregisterFQDNSelector removes this FQDNSelector from the set of
// IPs which are being tracked by the identityNotifier. The result
// of this is that an IP may be evicted from IPCache if it is no longer
// selected by any other FQDN selector.
func (n *manager) UnregisterFQDNSelector(selector api.FQDNSelector) (ipcacheRevision uint64) {
	n.Lock()
	defer n.Unlock()

	regex, _ := n.allSelectors[selector]
	// Remove selector
	delete(n.allSelectors, selector)
	if metrics.FQDNSelectors.IsEnabled() {
		metrics.FQDNSelectors.Set(float64(len(n.allSelectors)))
	}

	if selector.MatchName != "" {
		canon := prepareMatchName(selector.MatchName)
		if entry, ok := n.exactSelectors[canon]; ok {
			prevLen := len(entry.entries)
			entry.entries = slices.DeleteFunc(entry.entries, func(e selectorEntry) bool {
				return e.sel == selector
			})
			if len(entry.entries) == 0 {
				delete(n.exactSelectors, canon)
			} else if len(entry.entries) < prevLen {
				n.rebuildExactEntryLabels(canon, entry)
			}
		}
	}

	if selector.MatchPattern != "" {
		if suffix, ok := isSingleWildcardPrefix(selector.MatchPattern); ok {
			if sEntry, ok := n.suffixSelectors[suffix]; ok {
				prevLen := len(sEntry.entries)
				sEntry.entries = slices.DeleteFunc(sEntry.entries, func(e selectorEntry) bool {
					return e.sel == selector
				})
				if len(sEntry.entries) == 0 {
					delete(n.suffixSelectors, suffix)
				} else if len(sEntry.entries) < prevLen {
					sEntry.labels = make(labels.Labels, len(sEntry.entries))
					for _, entry := range sEntry.entries {
						sEntry.labels[entry.label.Key] = entry.label
					}
					sEntry.metadata = []ipcache.IPMetadata{sEntry.labels}
				}
				if len(sEntry.entries) < prevLen {
					for canon, e := range n.exactSelectors {
						if dot := strings.IndexByte(canon, '.'); dot > 0 && canon[dot+1:] == suffix {
							n.rebuildExactEntryLabels(canon, e)
						}
					}
				}
			}
		} else {
			prevLen := len(n.generalPatternSelectors)
			n.generalPatternSelectors = slices.DeleteFunc(n.generalPatternSelectors, func(e selectorEntry) bool {
				return e.sel == selector
			})
			if len(n.generalPatternSelectors) < prevLen {
				if regex == nil {
					regex, _ = selector.ToRegex()
				}
				if regex != nil {
					for canon, e := range n.exactSelectors {
						if regex.MatchString(canon) {
							n.rebuildExactEntryLabels(canon, e)
						}
					}
				}
			}
		}
	}

	if n.selectorChanges != nil {
		select {
		case n.selectorChanges <- selectorChange{sel: selector, added: false}:
		default:
			// No risk of correctness if this happens, but we will have leaked an identity.
			n.logger.Warn("failed to queue selector identity release")
		}
	}

	// Re-compute labels for affected names and IPs
	selectedNamesAndIPs := n.mapSelectorsToNamesLocked(selector, regex)
	if len(selectedNamesAndIPs) == 0 {
		return 0
	}
	return n.updateMetadata(n.deriveLabelsForNames(selectedNamesAndIPs))
}

// UpdateGenerateDNS inserts the new DNS information into the cache. If the IPs
// have changed for a name they will be reflected in updatedDNSIPs.
func (n *manager) UpdateGenerateDNS(ctx context.Context, lookupTime time.Time, name string, record *fqdn.DNSIPRecords, caches ...*fqdn.DNSCache) <-chan error {
	n.RWMutex.Lock()
	defer n.RWMutex.Unlock()

	// Update IPs in n
	res, ipcacheRevision := n.updateDNSIPs(lookupTime, name, record, caches...)
	if res.Upserted {
		if n.logger.Enabled(context.Background(), slog.LevelDebug) {
			n.logger.Debug(
				"Updated FQDN with new IPs",
				logfields.MatchName, name,
				logfields.IPAddrs, record.IPs,
			)
		}
	}

	c := make(chan error)
	go func() {
		c <- n.params.IPCache.WaitForRevision(ctx, ipcacheRevision)
	}()
	return c
}

// waitForEndpointRestore is a one-shot job. It waits for
// all endpoints to be regenerated.
func (n *manager) waitForEndpointRestore(ctx context.Context) error {
	epRestorer, err := n.params.RestorerPromise.Await(ctx)
	if err != nil {
		n.logger.Error("Failed to get endpoint restorer", logfields.Error, err)
		return err
	}
	if err := epRestorer.WaitForEndpointRestore(ctx); err != nil {
		n.logger.Error("Failed to wait for endpoints to regenerate", logfields.Error, err)
		return err
	}

	n.Lock()
	defer n.Unlock()

	n.bootstrapCompleted = true
	return nil
}

// updateDNSIPs updates the IPs for a DNS name. It returns whether the name's IPs
// changed and ipcacheRevision, a revision number to pass to WaitForRevision()
func (n *manager) updateDNSIPs(lookupTime time.Time, dnsName string, lookupIPs *fqdn.DNSIPRecords, caches ...*fqdn.DNSCache) (res fqdn.UpdateStatus, ipcacheRevision uint64) {
	res = n.updateIPsForName(lookupTime, dnsName, lookupIPs.IPs, lookupIPs.TTL, caches...)

	// The IPs didn't change. No more to be done for this dnsName
	if !res.Upserted && n.bootstrapCompleted {
		if n.logger.Enabled(context.Background(), slog.LevelDebug) {
			n.logger.Debug(
				"FQDN: IPs didn't change for DNS name",
				logfields.DNSName, dnsName,
				logfields.LookupIPAddrs, lookupIPs,
			)
		}
		return
	}

	// accumulate the new labels affected by new IPs
	if len(n.allSelectors) == 0 {
		if n.logger.Enabled(context.Background(), slog.LevelDebug) {
			n.logger.Debug(
				"FQDN: No selectors registered for updates",
				logfields.DNSName, dnsName,
				logfields.LookupIPAddrs, lookupIPs,
			)
		}
		return
	}

	// derive labels for this DNS name
	nameLabels, metadataSlice, resource := n.deriveLabelsAndMetadata(dnsName)
	if len(nameLabels) == 0 {
		// If no selectors care about this name, then skip IPCache updates
		// for this name.
		// If any selectors/ are added later, ipcache insertion will happen then.
		return
	}

	// If new IPs were detected, and these IPs are selected by selectors,
	// then ensure they have an identity allocated to them via the ipcache.
	ipcacheRevision = n.updateMetadataForName(dnsName, lookupIPs.IPs, nameLabels, metadataSlice, resource)
	return res, ipcacheRevision
}

// updateMetadataForName directly updates the metadata in IPCache for a single
// DNS name and its associated IP addresses.
func (n *manager) updateMetadataForName(dnsName string, addrs []netip.Addr, nameLabels labels.Labels, metadataSlice []ipcache.IPMetadata, resource ipcacheTypes.ResourceID) (ipcacheRevision uint64) {
	if len(addrs) == 0 {
		return 0
	}

	if n.logger.Enabled(context.Background(), slog.LevelDebug) {
		n.logger.Debug(
			"Updating prefix labels in IPCache",
			logfields.Name, dnsName,
			logfields.IPAddrs, addrs,
			logfields.Labels, nameLabels,
		)
	}

	updates := make([]ipcache.MU, len(addrs))
	if resource == "" {
		resource = ipcacheResource(dnsName)
	}
	if metadataSlice == nil {
		metadataSlice = []ipcache.IPMetadata{nameLabels}
	}

	for i, addr := range addrs {
		updates[i] = ipcache.MU{
			Prefix:   cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(addr, addr.BitLen())),
			Source:   source.Generated,
			Resource: resource,
			Metadata: metadataSlice,
		}
	}

	if len(nameLabels) > 0 {
		return n.params.IPCache.UpsertMetadataBatch(updates...)
	}
	return n.params.IPCache.RemoveMetadataBatch(updates...)
}

// updateIPsName will update the IPs for dnsName. It always retains a copy of
// newIPs.
// upserted is true when the new IPs differ from the old IPs
func (n *manager) updateIPsForName(lookupTime time.Time, dnsName string, newIPs []netip.Addr, ttl int, caches ...*fqdn.DNSCache) fqdn.UpdateStatus {
	return n.cache.Update(lookupTime, dnsName, newIPs, ttl, caches...)
}

func ipcacheResource(dnsName string) ipcacheTypes.ResourceID {
	return ipcacheTypes.ResourceID("daemon/fqdn-name-manager/" + dnsName)
}

// updateMetadata updates (i.e. upserts or removes) the metadata in IPCache for
// each (name, IP) pair provided in nameToMetadata.
func (n *manager) updateMetadata(nameToMetadata map[string]nameMetadata) (ipcacheRevision uint64) {
	var ipcacheUpserts, ipcacheRemovals []ipcache.MU

	for dnsName, metadata := range nameToMetadata {
		var updates []ipcache.MU
		resource := ipcacheResource(dnsName)

		if n.logger.Enabled(context.Background(), slog.LevelDebug) {
			n.logger.Debug(
				"Updating prefix labels in IPCache",
				logfields.Name, dnsName,
				logfields.IPAddrs, metadata.addrs,
				logfields.Labels, metadata.labels,
			)
		}

		for _, addr := range metadata.addrs {
			updates = append(updates, ipcache.MU{
				Prefix:   cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(addr, addr.BitLen())),
				Source:   source.Generated,
				Resource: resource,
				Metadata: []ipcache.IPMetadata{
					metadata.labels,
				},
			})
		}

		// If labels are empty (i.e. this domain is no longer selected),
		// then we want to the labels of our resource owner
		if len(metadata.labels) > 0 {
			ipcacheUpserts = append(ipcacheUpserts, updates...)
		} else {
			ipcacheRemovals = append(ipcacheRemovals, updates...)
		}
	}

	if len(ipcacheUpserts) > 0 {
		ipcacheRevision = n.params.IPCache.UpsertMetadataBatch(ipcacheUpserts...)
	}
	if len(ipcacheRemovals) > 0 {
		ipcacheRevision = n.params.IPCache.RemoveMetadataBatch(ipcacheRemovals...)
	}

	return ipcacheRevision
}

// maybeRemoveMetadata removes the ipcache metadata from every (name, IP) pair
// in maybeRemoved, as long as that (name, IP) is not still in the dns cache.
func (n *manager) maybeRemoveMetadata(maybeRemoved map[netip.Addr][]string) {
	// Need to take an RLock here so that no DNS updates are processed.
	// Otherwise, we might accidentally remove an IP that is newly inserted.
	n.RWMutex.RLock()
	defer n.RWMutex.RUnlock()

	n.cache.RemoveKnown(maybeRemoved)
	ipCacheUpdates := make([]ipcache.MU, 0, len(maybeRemoved))
	for ip, names := range maybeRemoved {
		for _, name := range names {
			ipCacheUpdates = append(ipCacheUpdates, ipcache.MU{
				Prefix:   cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(ip, ip.BitLen())),
				Source:   source.Generated,
				Resource: ipcacheResource(name),
				Metadata: []ipcache.IPMetadata{
					labels.Labels{}, // remove all labels for this (ip, name) pair
				},
			})
		}
	}
	n.params.IPCache.RemoveMetadataBatch(ipCacheUpdates...)
}

// LockName is used to serialize  parallel end-to-end updates to the same name.
//
// It is needed due to some subtleties around NameManager locks and
// policy updates. Specifically, we unlock the NameManager after updates
// are queued to endpoints, but *before* changes are pushed to policy maps.
// So, if a second request comes in during this state, it may encounter
// policy drops until the policy updates are complete.
//
// Serializing on names prevents this.
//
// Rather than having a potentially unbounded set of per-name locks, this
// buckets names in to a set of locks. The lock count is configurable.
func (n *manager) LockName(name string) {
	idx := nameLockIndex(name, n.params.Config.DNSProxyLockCount)
	n.nameLocks[idx].Lock()
}

// UnlockName releases a lock previously acquired by LockName()
func (n *manager) UnlockName(name string) {
	idx := nameLockIndex(name, n.params.Config.DNSProxyLockCount)
	n.nameLocks[idx].Unlock()
}

// nameLockIndex hashes the DNS name to a uint32, then returns that
// mod the bucket count.
func nameLockIndex(name string, cnt int) uint32 {
	h := fnv.New32()
	_, _ = h.Write([]byte(name)) // cannot return error
	return h.Sum32() % uint32(cnt)
}

type nameMetadata struct {
	addrs  []netip.Addr
	labels labels.Labels // if empty, metadata will be removed for this name
}

// deriveLabelsForName derives what `fqdn:` labels we want to associate with
// IPs for this DNS name using the partitioned index of exact, suffix, and pattern selectors.
func (n *manager) deriveLabelsForName(dnsName string) labels.Labels {
	lbls, _, _ := n.deriveLabelsAndMetadata(dnsName)
	return lbls
}

func (n *manager) deriveLabelsAndMetadata(dnsName string) (labels.Labels, []ipcache.IPMetadata, ipcacheTypes.ResourceID) {
	// Fast path 1: Exact domain match in exactSelectors
	if entry, found := n.exactSelectors[dnsName]; found {
		return entry.labels, entry.metadata, entry.resource
	}

	var matchedLabels labels.Labels
	var matchedMetadata []ipcache.IPMetadata
	var matchCount int

	// Fast path 2: Suffix wildcard match in suffixSelectors
	if dot := strings.IndexByte(dnsName, '.'); dot > 0 {
		suffix := dnsName[dot+1:]
		if sEntry, found := n.suffixSelectors[suffix]; found {
			matchCount++
			matchedLabels = sEntry.labels
			matchedMetadata = sEntry.metadata
		}
	}

	// Fallback: General regex pattern scan if any general patterns exist
	if len(n.generalPatternSelectors) > 0 {
		for _, entry := range n.generalPatternSelectors {
			if entry.regex.MatchString(dnsName) {
				matchCount++
				if matchCount == 1 {
					matchedLabels = entry.labels
					matchedMetadata = entry.metadata
				} else if matchCount == 2 {
					multiLabels := make(labels.Labels, len(matchedLabels)+1)
					for k, v := range matchedLabels {
						multiLabels[k] = v
					}
					multiLabels[entry.label.Key] = entry.label
					matchedLabels = multiLabels
					matchedMetadata = []ipcache.IPMetadata{matchedLabels}
				} else {
					matchedLabels[entry.label.Key] = entry.label
				}
			}
		}
	}

	if matchCount == 0 {
		return labels.Labels{}, nil, ""
	}
	return matchedLabels, matchedMetadata, ipcacheResource(dnsName)
}

// deriveLabelsForNames derives the labels for all names found in nameToIPs
func (n *manager) deriveLabelsForNames(nameToIPs map[string][]netip.Addr) (namesWithMetadata map[string]nameMetadata) {
	namesWithMetadata = make(map[string]nameMetadata, len(nameToIPs))
	for dnsName, addrs := range nameToIPs {
		namesWithMetadata[dnsName] = nameMetadata{
			addrs:  addrs,
			labels: n.deriveLabelsForName(dnsName),
		}
	}
	return namesWithMetadata
}

// deriveLabelsForName derives what `fqdn:` labels we want to associate with
// IPs for this DNS name, i.e. what selectors match the DNS name.
func deriveLabelsForName(dnsName string, selectors map[api.FQDNSelector]*regexp.Regexp) labels.Labels {
	lbls := labels.Labels{}
	for fqdnSel, fqdnRegex := range selectors {
		matches := fqdnRegex.MatchString(dnsName)
		if matches {
			l := fqdnSel.IdentityLabel()
			lbls[l.Key] = l
		}
	}
	return lbls
}

// deriveLabelsForNames derives the labels for all names found in nameToIPs
func deriveLabelsForNames(nameToIPs map[string][]netip.Addr, selectors map[api.FQDNSelector]*regexp.Regexp) (namesWithMetadata map[string]nameMetadata) {
	namesWithMetadata = make(map[string]nameMetadata, len(nameToIPs))
	for dnsName, addrs := range nameToIPs {
		namesWithMetadata[dnsName] = nameMetadata{
			addrs:  addrs,
			labels: deriveLabelsForName(dnsName, selectors),
		}
	}
	return namesWithMetadata
}

// mapSelectorsToNamesLocked iterates through all DNS Names in the cache and
// evaluates if they match the provided fqdnSelector. If so, the matching DNS
// Name with all its associated IPs is collected.
//
// Returns the mapping of DNS names to all IPs selected by that selector.
func (n *manager) mapSelectorsToNamesLocked(fqdnSelector api.FQDNSelector, regexes ...*regexp.Regexp) (namesIPMapping map[string][]netip.Addr) {
	namesIPMapping = make(map[string][]netip.Addr)

	// lookup matching DNS names
	if len(fqdnSelector.MatchName) > 0 {
		dnsName := prepareMatchName(fqdnSelector.MatchName)
		lookupIPs := n.cache.Lookup(dnsName)
		if len(lookupIPs) > 0 {
			if n.logger.Enabled(context.Background(), slog.LevelDebug) {
				n.logger.Debug(
					"Emitting matching DNS Name -> IPs for FQDNSelector",
					logfields.DNSName, dnsName,
					logfields.IPAddrs, lookupIPs,
					logfields.MatchName, fqdnSelector.MatchName,
				)
			}
			namesIPMapping[dnsName] = lookupIPs
		}
	}

	if len(fqdnSelector.MatchPattern) > 0 {
		var patternRE *regexp.Regexp
		if len(regexes) > 0 && regexes[0] != nil {
			patternRE = regexes[0]
		} else if existingRE, ok := n.allSelectors[fqdnSelector]; ok && existingRE != nil {
			patternRE = existingRE
		} else {
			// lookup matching DNS names
			dnsPattern := matchpattern.Sanitize(fqdnSelector.MatchPattern)
			patternREStr := matchpattern.ToAnchoredRegexp(dnsPattern)
			var err error
			if patternRE, err = re.CompileRegex(patternREStr); err != nil {
				n.logger.Error("Error compiling matchPattern", logfields.Error, err)
				return namesIPMapping
			}
		}
		lookupIPs := n.cache.LookupByRegexp(patternRE)

		for dnsName, ips := range lookupIPs {
			if len(ips) > 0 {
				if n.logger.Enabled(context.Background(), slog.LevelDebug) {
					n.logger.Debug(
						"Emitting matching DNS Name -> IPs for FQDNSelector",
						logfields.DNSName, dnsName,
						logfields.IPAddrs, ips,
						logfields.MatchPattern, fqdnSelector.MatchPattern,
					)
				}
				namesIPMapping[dnsName] = append(namesIPMapping[dnsName], ips...)
			}
		}
	}

	return namesIPMapping
}

// prepareMatchName ensures a ToFQDNs.matchName field is used consistently.
func prepareMatchName(matchName string) string {
	return dns.FQDN(matchName)
}
