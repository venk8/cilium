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

	mu            lock.RWMutex
	cookieSet     *bitset
	cookieToValue []V
	inUseBits     [4]uint64
	inUseExtra    []uint64
}

var _ Bakery[uint32, string] = (*bakery[uint32, string])(nil)

// maxOf returns the maximum value for unsigned type T.
func maxOf[T constraints.Unsigned]() T {
	var zero T
	return ^zero
}

// NewBakery creates a new Bakery. It manages cookies of type C for values of type V.
func NewBakery[C constraints.Unsigned, V comparable](logger *slog.Logger) *bakery[C, V] {
	return &bakery[C, V]{
		logger:        logger,
		cookieSet:     newBitset(int(maxOf[C]())),
		cookieToValue: nil,
	}
}

func (b *bakery[C, V]) markInUse(idx int) {
	if idx < 0 {
		return
	}
	word := idx / 64
	mask := uint64(1) << (idx % 64)
	if word < len(b.inUseBits) {
		b.inUseBits[word] |= mask
		return
	}
	extraIdx := word - len(b.inUseBits)
	for len(b.inUseExtra) <= extraIdx {
		b.inUseExtra = append(b.inUseExtra, 0)
	}
	b.inUseExtra[extraIdx] |= mask
}

func (b *bakery[C, V]) isInUse(idx int) bool {
	if idx < 0 {
		return false
	}
	word := idx / 64
	mask := uint64(1) << (idx % 64)
	if word < len(b.inUseBits) {
		return (b.inUseBits[word] & mask) != 0
	}
	extraIdx := word - len(b.inUseBits)
	if extraIdx < len(b.inUseExtra) {
		return (b.inUseExtra[extraIdx] & mask) != 0
	}
	return false
}

func (b *bakery[C, V]) resetInUse() {
	b.inUseBits = [4]uint64{}
	clear(b.inUseExtra)
}

// Allocate returns a unique, cookie for the given value and whether a cookie could be allocated or
// reused. A successfully allocated cookie is always non-zero. If no cookie could be allocated, a
// zero cookie is returned. If the same value is provided again, Allocate returns the previously
// allocated cookie for that value.
func (b *bakery[C, V]) Allocate(value V) (cookie C, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for idx := range b.cookieToValue {
		if b.cookieSet.IsSet(idx) && b.cookieToValue[idx] == value {
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
		b.cookieToValue[next] = value
	} else {
		var zero V
		for len(b.cookieToValue) < next {
			b.cookieToValue = append(b.cookieToValue, zero)
		}
		b.cookieToValue = append(b.cookieToValue, value)
	}
	b.markInUse(next)
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
	return b.cookieToValue[idx], true
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
		b.markInUse(idx)
	}
}

// Sweep removes all cookies not marked as in-use since the last time sweep cycle.
func (b *bakery[C, V]) Sweep() {
	b.mu.Lock()
	defer b.mu.Unlock()

	var zero V
	for idx := range b.cookieToValue {
		if b.cookieSet.IsSet(idx) {
			if !b.isInUse(idx) {
				cookie := C(idx + 1)
				// Correct for offset added during allocation. See comment in Allocate.
				b.cookieSet.Release(idx)
				if b.logger != nil && b.logger.Enabled(context.Background(), slog.LevelDebug) {
					b.logger.Debug("Released policy log cookie",
						logfields.PolicyLogCookie, cookie,
						logfields.PolicyLogCookie, b.cookieToValue[idx],
					)
				}
				b.cookieToValue[idx] = zero
			}
		}
	}
	n := len(b.cookieToValue)
	for n > 0 && !b.cookieSet.IsSet(n-1) {
		n--
	}
	b.cookieToValue = b.cookieToValue[:n]
	b.resetInUse()
}

// Count returns the number of allocated cookies.
func (b *bakery[C, V]) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.cookieSet.Count()
}
