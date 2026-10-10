// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"cmp"
	"encoding/json"
	"math/bits"
	"slices"
)

// ImmSet is an immutable set optimized for a smallish (1-1000) set of items.
// Implemented as a sorted slice.
type ImmSet[T any] struct {
	xs  []T
	cmp func(T, T) int
}

func NewImmSet[T cmp.Ordered](items ...T) ImmSet[T] {
	return NewImmSetFunc[T](cmp.Compare, items...)
}

func NewImmSetFunc[T any](compare func(T, T) int, items ...T) ImmSet[T] {
	if len(items) == 0 {
		return ImmSet[T]{cmp: compare}
	}
	xs := slices.Clone(items)
	slices.SortFunc(xs, compare)
	xs = slices.CompactFunc(xs, func(a, b T) bool { return compare(a, b) == 0 })
	return ImmSet[T]{xs: xs, cmp: compare}
}

// AsSlice returns the underlying slice stored in the immutable set.
// The caller is NOT allowed to modify the slice.
func (s ImmSet[T]) AsSlice() []T {
	return s.xs
}

func (s ImmSet[T]) Len() int {
	return len(s.xs)
}

func (s ImmSet[T]) Has(x T) bool {
	_, found := slices.BinarySearchFunc(s.xs, x, s.cmp)
	return found
}

func (s *ImmSet[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.xs)
}

func (s *ImmSet[T]) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &s.xs)
}

func (s ImmSet[T]) Insert(xs ...T) ImmSet[T] {
	if len(xs) == 0 {
		return s
	}
	if len(s.xs) == 0 {
		return NewImmSetFunc(s.cmp, xs...)
	}
	if len(xs) == 1 {
		idx, found := slices.BinarySearchFunc(s.xs, xs[0], s.cmp)
		if found {
			return s
		}
		xs2 := make([]T, len(s.xs)+1)
		copy(xs2[:idx], s.xs[:idx])
		xs2[idx] = xs[0]
		copy(xs2[idx+1:], s.xs[idx:])
		return ImmSet[T]{xs: xs2, cmp: s.cmp}
	}

	totalCap := len(s.xs) + len(xs)
	buf := make([]T, len(xs), totalCap)
	copy(buf, xs)
	slices.SortFunc(buf, s.cmp)
	buf = slices.CompactFunc(buf, func(a, b T) bool { return s.cmp(a, b) == 0 })
	m := len(buf)

	full := buf[:totalCap]
	offset := totalCap - m
	copy(full[offset:], buf)

	xs1 := s.xs
	xsSorted := full[offset:]
	out := full[:0]
	for len(xs1) > 0 && len(xsSorted) > 0 {
		switch diff := s.cmp(xs1[0], xsSorted[0]); {
		case diff < 0:
			out = append(out, xs1[0])
			xs1 = xs1[1:]
		case diff > 0:
			out = append(out, xsSorted[0])
			xsSorted = xsSorted[1:]
		default:
			out = append(out, xs1[0])
			xs1 = xs1[1:]
			xsSorted = xsSorted[1:]
		}
	}
	out = append(out, xs1...)
	n := copy(full[len(out):], xsSorted)
	out = full[:len(out)+n]
	clear(full[len(out):])
	return ImmSet[T]{xs: out, cmp: s.cmp}
}

func (s ImmSet[T]) Delete(xs ...T) ImmSet[T] {
	if len(xs) == 0 || len(s.xs) == 0 {
		return s
	}
	if len(xs) > 1 {
		xsAsImmSet := NewImmSetFunc(s.cmp, xs...)
		return s.Difference(xsAsImmSet)
	}
	idx, found := slices.BinarySearchFunc(s.xs, xs[0], s.cmp)
	if !found {
		return s
	}
	xs2 := make([]T, len(s.xs)-1)
	copy(xs2[:idx], s.xs[:idx])
	copy(xs2[idx:], s.xs[idx+1:])
	return ImmSet[T]{xs: xs2, cmp: s.cmp}
}

func (s ImmSet[T]) Union(s2 ImmSet[T]) ImmSet[T] {
	if len(s.xs) == 0 {
		return s2
	}
	if len(s2.xs) == 0 {
		return s
	}
	result := make([]T, 0, len(s.xs)+len(s2.xs))
	xs1, xs2 := s.xs, s2.xs
	for len(xs1) > 0 && len(xs2) > 0 {
		switch diff := s.cmp(xs1[0], xs2[0]); {
		case diff < 0:
			result = append(result, xs1[0])
			xs1 = xs1[1:]
		case diff > 0:
			result = append(result, xs2[0])
			xs2 = xs2[1:]
		default:
			result = append(result, xs1[0])
			xs1 = xs1[1:]
			xs2 = xs2[1:]
		}
	}
	result = append(result, xs1...)
	result = append(result, xs2...)
	return ImmSet[T]{xs: result, cmp: s.cmp}
}

func (s ImmSet[T]) Difference(s2 ImmSet[T]) ImmSet[T] {
	if len(s.xs) == 0 || len(s2.xs) == 0 {
		return s
	}

	const maxStackWords = 256 // 256 * 64 = 16,384 elements (2 KB on stack)
	nWords := (len(s.xs) + 63) / 64
	var bitBuf [maxStackWords]uint64
	var bitsSlice []uint64
	if nWords <= maxStackWords {
		bitsSlice = bitBuf[:nWords]
	} else {
		bitsSlice = make([]uint64, nWords)
	}

	xs1, xs2 := s.xs, s2.xs
	i := 0
	count := 0
	for len(xs1) > 0 && len(xs2) > 0 {
		switch diff := s.cmp(xs1[0], xs2[0]); {
		case diff < 0:
			bitsSlice[i/64] |= uint64(1) << (i % 64)
			count++
			i++
			xs1 = xs1[1:]
		case diff > 0:
			xs2 = xs2[1:]
		default:
			i++
			xs1 = xs1[1:]
			xs2 = xs2[1:]
		}
	}
	for ; i < len(s.xs); i++ {
		bitsSlice[i/64] |= uint64(1) << (i % 64)
		count++
	}

	if count == len(s.xs) {
		return s
	}
	if count == 0 {
		return ImmSet[T]{cmp: s.cmp}
	}

	result := make([]T, count)
	dst := 0
	for wordIdx, word := range bitsSlice {
		if word == 0 {
			continue
		}
		base := wordIdx * 64
		for word != 0 {
			bit := bits.TrailingZeros64(word)
			result[dst] = s.xs[base+bit]
			dst++
			word &= word - 1
		}
	}
	return ImmSet[T]{xs: result, cmp: s.cmp}
}

func (s ImmSet[T]) Equal(s2 ImmSet[T]) bool {
	return slices.EqualFunc(s.xs, s2.xs, func(a, b T) bool { return s.cmp(a, b) == 0 })
}
