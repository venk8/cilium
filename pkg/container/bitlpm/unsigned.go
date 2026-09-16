// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bitlpm

import (
	"math/bits"
	"unsafe"
)

// Unsigned represents all types that have an underlying
// unsigned integer type, excluding uintptr and uint.
type Unsigned interface {
	~uint8 | ~uint16 | ~uint32 | ~uint64
}

// UintTrie uses all unsigned integer types
// except for uintptr and uint.
type UintTrie[K Unsigned, V any] struct {
	trie    *trie[unsignedKey[K], V]
	keySize uint
}

// NewUintTrie represents a Trie with a key of any
// uint type.
func NewUintTrie[K Unsigned, T any]() *UintTrie[K, T] {
	var k K
	size := uint(unsafe.Sizeof(k))
	return &UintTrie[K, T]{
		trie:    newTrie[unsignedKey[K], T](size * 8),
		keySize: size,
	}
}

func (ut *UintTrie[K, T]) Upsert(prefix uint, k K, value T) bool {
	return ut.trie.Upsert(prefix, unsignedKey[K]{value: k}, value)
}

func (ut *UintTrie[K, T]) Delete(prefix uint, k K) bool {
	return ut.trie.Delete(prefix, unsignedKey[K]{value: k})
}

func (ut *UintTrie[K, T]) ExactLookup(prefix uint, k K) (T, bool) {
	return ut.trie.ExactLookup(prefix, unsignedKey[K]{value: k})
}

func (ut *UintTrie[K, T]) LongestPrefixMatch(k K) (K, T, bool) {
	k2, v, ok := ut.trie.LongestPrefixMatch(unsignedKey[K]{value: k})
	if ok {
		return k2.value, v, ok
	}
	var empty K
	return empty, v, ok
}

func (ut *UintTrie[K, T]) Ancestors(prefix uint, k K, fn func(prefix uint, key K, value T) bool) {
	prefix = min(prefix, ut.trie.maxPrefix)
	key := unsignedKey[K]{value: k}
	for currentNode := ut.trie.root; currentNode != nil; currentNode = currentNode.children[key.BitValueAt(currentNode.prefixLen)] {
		matchLen := currentNode.prefixMatch(prefix, key)
		if matchLen < currentNode.prefixLen {
			return
		}
		if currentNode.intermediate {
			continue
		}
		if !fn(currentNode.prefixLen, currentNode.key.value, currentNode.value) || matchLen == ut.trie.maxPrefix {
			return
		}
	}
}

func (ut *UintTrie[K, T]) Descendants(prefix uint, k K, fn func(prefix uint, key K, value T) bool) {
	ut.trie.Descendants(prefix, unsignedKey[K]{value: k}, func(prefix uint, k unsignedKey[K], v T) bool {
		return fn(prefix, k.value, v)
	})
}

func (ut *UintTrie[K, T]) Len() uint {
	return ut.trie.Len()
}

func (ut *UintTrie[K, T]) ForEach(fn func(prefix uint, key K, value T) bool) {
	ut.trie.ForEach(func(prefix uint, k unsignedKey[K], v T) bool {
		return fn(prefix, k.value, v)
	})
}

type unsignedKey[U Unsigned] struct {
	value U
}

func (u unsignedKey[U]) CommonPrefix(v unsignedKey[U]) uint {
	switch unsafe.Sizeof(u.value) {
	case 1:
		return uint(bits.LeadingZeros8(uint8(u.value ^ v.value)))
	case 2:
		return uint(bits.LeadingZeros16(uint16(u.value ^ v.value)))
	case 4:
		return uint(bits.LeadingZeros32(uint32(u.value ^ v.value)))
	case 8:
		return uint(bits.LeadingZeros64(uint64(u.value ^ v.value)))
	}
	return 0
}

func (u unsignedKey[U]) BitValueAt(i uint) uint8 {
	switch unsafe.Sizeof(u.value) {
	case 1:
		return uint8((uint8(u.value) >> (7 - i)) & 1)
	case 2:
		return uint8((uint16(u.value) >> (15 - i)) & 1)
	case 4:
		return uint8((uint32(u.value) >> (31 - i)) & 1)
	case 8:
		return uint8((uint64(u.value) >> (63 - i)) & 1)
	}
	return 0
}
