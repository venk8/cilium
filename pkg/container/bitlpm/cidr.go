// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bitlpm

import (
	"math/bits"
	"net/netip"
	"unsafe"
)

// CIDRTrie can hold both IPv4 and IPv6 prefixes
// at the same time.
type CIDRTrie[T any] struct {
	v4 *trie[cidrKey, T]
	v6 *trie[cidrKey, T]
}

// NewCIDRTrie creates a new CIDRTrie[T any].
func NewCIDRTrie[T any]() *CIDRTrie[T] {
	return &CIDRTrie[T]{
		v4: newTrie[cidrKey, T](32),
		v6: newTrie[cidrKey, T](128),
	}
}

// ExactLookup returns the value for a given CIDR, but only
// if there is an exact match for the CIDR in the Trie.
func (c *CIDRTrie[T]) ExactLookup(cidr netip.Prefix) (T, bool) {
	return c.treeForFamily(cidr).ExactLookup(uint(cidr.Bits()), cidrKey(cidr))
}

// LongestPrefixMatch returns the longest matched value for a given address.
func (c *CIDRTrie[T]) LongestPrefixMatch(addr netip.Addr) (netip.Prefix, T, bool) {
	if !addr.IsValid() {
		var p netip.Prefix
		var def T
		return p, def, false
	}
	bits := addr.BitLen()
	prefix := netip.PrefixFrom(addr, bits)
	k, v, ok := c.treeForFamily(prefix).LongestPrefixMatch(cidrKey(prefix))
	if ok {
		return netip.Prefix(k), v, ok
	}
	var p netip.Prefix
	return p, v, ok
}

// Ancestors iterates over every CIDR pair that contains the CIDR argument.
func (c *CIDRTrie[T]) Ancestors(cidr netip.Prefix, fn func(k netip.Prefix, v T) bool) {
	t := c.treeForFamily(cidr)
	prefixLen := min(uint(cidr.Bits()), t.maxPrefix)
	k := cidrKey(cidr)
	for currentNode := t.root; currentNode != nil; currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)] {
		matchLen := currentNode.prefixMatch(prefixLen, k)
		if matchLen < currentNode.prefixLen {
			return
		}
		if currentNode.intermediate {
			continue
		}
		if !fn(netip.Prefix(currentNode.key), currentNode.value) || matchLen == t.maxPrefix {
			return
		}
	}
}

func (c *CIDRTrie[T]) AncestorIterator(cidr netip.Prefix) ancestorIterator[cidrKey, T] {
	return c.treeForFamily(cidr).AncestorIterator(uint(cidr.Bits()), cidrKey(cidr))
}

// AncestorsLongestPrefixFirst iterates over every CIDR pair that contains the CIDR argument,
// longest matching prefix first, then iterating towards the root of the trie.
func (c *CIDRTrie[T]) AncestorsLongestPrefixFirst(cidr netip.Prefix, fn func(k netip.Prefix, v T) bool) {
	t := c.treeForFamily(cidr)
	prefixLen := min(uint(cidr.Bits()), t.maxPrefix)
	k := cidrKey(cidr)
	var buf [32]*node[cidrKey, T]
	stack := buf[:0]
	for currentNode := t.root; currentNode != nil; currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)] {
		matchLen := currentNode.prefixMatch(prefixLen, k)
		if matchLen < currentNode.prefixLen {
			break
		}
		if currentNode.intermediate {
			continue
		}
		stack = append(stack, currentNode)
		if matchLen == t.maxPrefix {
			break
		}
	}
	for i := len(stack) - 1; i >= 0; i-- {
		n := stack[i]
		if !fn(netip.Prefix(n.key), n.value) {
			return
		}
	}
}

func (c *CIDRTrie[T]) AncestorLongestPrefixFirstIterator(cidr netip.Prefix) ancestorLPFIterator[cidrKey, T] {
	return c.treeForFamily(cidr).AncestorLongestPrefixFirstIterator(uint(cidr.Bits()), cidrKey(cidr))
}

// Descendants iterates over every CIDR that is contained by the CIDR argument.
func (c *CIDRTrie[T]) Descendants(cidr netip.Prefix, fn func(k netip.Prefix, v T) bool) {
	t := c.treeForFamily(cidr)
	prefixLen := min(uint(cidr.Bits()), t.maxPrefix)
	k := cidrKey(cidr)
	currentNode := t.root
	for currentNode != nil {
		matchLen := currentNode.prefixMatch(prefixLen, k)
		if matchLen >= prefixLen {
			forEachCIDR(currentNode, fn)
			return
		}
		if currentNode.prefixLen >= t.maxPrefix {
			return
		}
		currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)]
	}
}

func forEachCIDR[T any](n *node[cidrKey, T], fn func(k netip.Prefix, v T) bool) {
	if !n.intermediate {
		if !fn(netip.Prefix(n.key), n.value) {
			return
		}
	}
	if n.children[0] != nil {
		forEachCIDR(n.children[0], fn)
	}
	if n.children[1] != nil {
		forEachCIDR(n.children[1], fn)
	}
}

func forEachShortestPrefixFirstCIDR[T any](n *node[cidrKey, T], fn func(k netip.Prefix, v T) bool) {
	var buf [16]*node[cidrKey, T]
	nodes := nodes[cidrKey, T](buf[:0])
	nodes.pushHeap(n)

	for nodes.Len() > 0 {
		n := nodes.popHeap()
		if !n.intermediate {
			if !fn(netip.Prefix(n.key), n.value) {
				return
			}
		}
		if n.children[0] != nil {
			nodes.pushHeap(n.children[0])
		}
		if n.children[1] != nil {
			nodes.pushHeap(n.children[1])
		}
	}
}

func (c *CIDRTrie[T]) DescendantIterator(cidr netip.Prefix) descendantIterator[cidrKey, T] {
	return c.treeForFamily(cidr).DescendantIterator(uint(cidr.Bits()), cidrKey(cidr))
}

// DescendantsShortestPrefixFirst iterates over every CIDR that is contained by the CIDR argument.
func (c *CIDRTrie[T]) DescendantsShortestPrefixFirst(cidr netip.Prefix, fn func(k netip.Prefix, v T) bool) {
	t := c.treeForFamily(cidr)
	prefixLen := min(uint(cidr.Bits()), t.maxPrefix)
	k := cidrKey(cidr)
	currentNode := t.root
	for currentNode != nil {
		matchLen := currentNode.prefixMatch(prefixLen, k)
		if matchLen >= prefixLen {
			forEachShortestPrefixFirstCIDR(currentNode, fn)
			return
		}
		if currentNode.prefixLen >= t.maxPrefix {
			return
		}
		currentNode = currentNode.children[k.BitValueAt(currentNode.prefixLen)]
	}
}

func (c *CIDRTrie[T]) DescendantShortestPrefixFirstIterator(cidr netip.Prefix) descendantSPFIterator[cidrKey, T] {
	return c.treeForFamily(cidr).DescendantShortestPrefixFirstIterator(uint(cidr.Bits()), cidrKey(cidr))
}

// Upsert adds or updates the value for a given prefix.
func (c *CIDRTrie[T]) Upsert(cidr netip.Prefix, v T) bool {
	return c.treeForFamily(cidr).Upsert(uint(cidr.Bits()), cidrKey(cidr), v)
}

// Delete removes a given prefix from the tree.
func (c *CIDRTrie[T]) Delete(cidr netip.Prefix) bool {
	return c.treeForFamily(cidr).Delete(uint(cidr.Bits()), cidrKey(cidr))
}

// Len returns the total number of ipv4 and ipv6 prefixes in the trie.
func (c *CIDRTrie[T]) Len() uint {
	return c.v4.Len() + c.v6.Len()
}

// ForEach iterates over every element of the Trie. It iterates over IPv4
// keys first.
func (c *CIDRTrie[T]) ForEach(fn func(k netip.Prefix, v T) bool) {
	var v4Break bool
	c.v4.ForEach(func(prefix uint, k cidrKey, v T) bool {
		if !fn(netip.Prefix(k), v) {
			v4Break = true
			return false
		}
		return true
	})
	if !v4Break {
		c.v6.ForEach(func(prefix uint, k cidrKey, v T) bool {
			return fn(netip.Prefix(k), v)
		})
	}

}

func (c *CIDRTrie[T]) treeForFamily(cidr netip.Prefix) *trie[cidrKey, T] {
	if cidr.Addr().Is6() {
		return c.v6
	}
	return c.v4
}

type cidrKey netip.Prefix

func (k cidrKey) BitValueAt(idx uint) uint8 {
	words := (*[2]uint64)(unsafe.Pointer(&k))
	if netip.Prefix(k).Addr().Is4() {
		return uint8((words[1] >> (31 - idx)) & 1)
	}
	if idx < 64 {
		return uint8((words[0] >> (63 - idx)) & 1)
	}
	return uint8((words[1] >> (127 - idx)) & 1)
}

func (k cidrKey) CommonPrefix(k2 cidrKey) uint {
	words1 := (*[2]uint64)(unsafe.Pointer(&k))
	words2 := (*[2]uint64)(unsafe.Pointer(&k2))
	if netip.Prefix(k).Addr().Is4() {
		word1 := uint32(words1[1])
		word2 := uint32(words2[1])
		return uint(bits.LeadingZeros32(word1 ^ word2))
	}
	v := bits.LeadingZeros64(words1[0] ^ words2[0])
	if v == 64 {
		v += bits.LeadingZeros64(words1[1] ^ words2[1])
	}
	return uint(v)
}
