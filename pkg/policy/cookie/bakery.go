// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cookie

import (
	"context"
	"log/slog"

	"golang.org/x/exp/constraints"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Bakery allocates unique unsigned integer cookies of type C for a comparable value of type. It
// allows looking up the value for a given cookie and mark-and-sweep garbage collection.
type Bakery[C constraints.Unsigned, V comparable] interface {
	// Allocate returns a unique, cookie for the given value and whether a cookie could be
	// allocated or reused. A successfully allocated cookie is always non-zero. If no cookie
	// could be allocated, a zero cookie is returned. If the same value is provided again,
	// Allocate returns the previously allocated cookie for that value.
	Allocate(value V) (cookie C, ok bool)
	// Get returns the value for a given cookie and whether it exists in the bakery. If the
	// cookie doesn't exist, a zero value will be returned.
	Get(cookie C) (value V, exists bool)
	// MarkInUse marks a cookie as in-use for the next sweep.
	MarkInUse(cookie C)
	// Sweep removes all cookies not marked as in-use since the last time sweep cycle.
	Sweep()
	// Count returns the number of allocated cookies.
	Count() int
}

type bakery[C constraints.Unsigned, V comparable] struct {
	logger *slog.Logger

	mu                 lock.RWMutex
	cookieSet          *bitset
	cookieToValue      []entry[V]
	lastSeenGeneration uint64
}

var _ Bakery[uint32, string] = (*bakery[uint32, string])(nil)

type entry[T comparable] struct {
	value T
	since uint64
}

// maxOf returns the maximum value for unsigned type T.
func maxOf[T constraints.Unsigned]() T {
	var zero T
	return ^zero
}

// NewBakery creates a new Bakery. It manages cookies of type C for values of type V.
func NewBakery[C constraints.Unsigned, V comparable](logger *slog.Logger) *bakery[C, V] {
	return &bakery[C, V]{
		logger:             logger,
		cookieSet:          newBitset(int(maxOf[C]())),
		cookieToValue:      nil,
		lastSeenGeneration: 0,
	}
}

// Allocate returns a unique, cookie for the given value and whether a cookie could be allocated or
// reused. A successfully allocated cookie is always non-zero. If no cookie could be allocated, a
// zero cookie is returned. If the same value is provided again, Allocate returns the previously
// allocated cookie for that value.
func (b *bakery[C, V]) Allocate(value V) (cookie C, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for idx := range b.cookieToValue {
		if b.cookieSet.IsSet(idx) && b.cookieToValue[idx].value == value {
			return C(idx + 1), true
		}
	}
	next, ok := b.cookieSet.Allocate()
	if !ok {
		return 0, false
	}
	// Offset of 1 because a non-zero cookie is needed. Cookie value 0 means no cookie.
	cookie = C(next + 1)
	if next < len(b.cookieToValue) {
		b.cookieToValue[next] = entry[V]{value: value, since: b.lastSeenGeneration}
	} else {
		for len(b.cookieToValue) < next {
			b.cookieToValue = append(b.cookieToValue, entry[V]{})
		}
		b.cookieToValue = append(b.cookieToValue, entry[V]{value: value, since: b.lastSeenGeneration})
	}
	if b.logger != nil && b.logger.Enabled(context.Background(), slog.LevelDebug) {
		b.logger.Debug("Allocated policy log cookie",
			logfields.PolicyLogCookie, cookie,
			logfields.PolicyLogString, value,
		)
	}
	return cookie, true
}

// Get returns the value for a given cookie and whether it exists in the bakery. If the cookie
// doesn't exist, a zero value will be returned.
func (b *bakery[C, V]) Get(cookie C) (value V, exists bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if cookie == 0 {
		return value, false
	}
	idx := int(cookie - 1)
	if idx < 0 || idx >= len(b.cookieToValue) || !b.cookieSet.IsSet(idx) {
		return value, false
	}
	return b.cookieToValue[idx].value, true
}

// MarkInUse marks a cookie as in-use for the next sweep.
func (b *bakery[C, V]) MarkInUse(cookie C) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if cookie == 0 {
		return
	}
	idx := int(cookie - 1)
	if idx >= 0 && idx < len(b.cookieToValue) && b.cookieSet.IsSet(idx) {
		b.cookieToValue[idx].since = b.lastSeenGeneration
	}
}

// Sweep removes all cookies not marked as in-use since the last time sweep cycle.
func (b *bakery[C, V]) Sweep() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for idx := range b.cookieToValue {
		if b.cookieSet.IsSet(idx) {
			e := &b.cookieToValue[idx]
			if e.since < b.lastSeenGeneration {
				cookie := C(idx + 1)
				// Correct for offset added during allocation. See comment in Allocate.
				b.cookieSet.Release(idx)
				if b.logger != nil && b.logger.Enabled(context.Background(), slog.LevelDebug) {
					b.logger.Debug("Released policy log cookie",
						logfields.PolicyLogCookie, cookie,
						logfields.PolicyLogCookie, e.value,
					)
				}
				*e = entry[V]{}
			}
		}
	}
	n := len(b.cookieToValue)
	for n > 0 && !b.cookieSet.IsSet(n-1) {
		n--
	}
	b.cookieToValue = b.cookieToValue[:n]
	b.lastSeenGeneration++
}

// Count returns the number of allocated cookies.
func (b *bakery[C, V]) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.cookieSet.Count()
}
