// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package set

import (
	"fmt"
	"iter"
	"maps"
)

type empty struct{}

// Set contains zero, one, or more members. Zero or one members do not consume any additional
// storage, more than one members are held in an non-exported membersMap.
type Set[T comparable] struct {
	single    T
	hasSingle bool
	members   map[T]empty
}

// Empty returns 'true' if the set is empty.
func (s Set[T]) Empty() bool {
	return !s.hasSingle && s.members == nil
}

// Len returns the number of members in the set.
func (s Set[T]) Len() int {
	if s.hasSingle {
		return 1
	}
	return len(s.members)
}

func (s Set[T]) String() string {
	if s.hasSingle {
		return fmt.Sprintf("%v", s.single)
	}
	res := ""
	for m := range s.members {
		if res != "" {
			res += ","
		}
		res += fmt.Sprintf("%v", m)
	}
	return res
}

// NewSingleSet returns a Set initialized to contain a single member without variadic slice allocation.
func NewSingleSet[T comparable](member T) Set[T] {
	return Set[T]{single: member, hasSingle: true}
}

// NewSet returns a Set initialized to contain the members in 'members'.
func NewSet[T comparable](members ...T) Set[T] {
	if len(members) == 0 {
		return Set[T]{}
	}
	if len(members) == 1 {
		return Set[T]{single: members[0], hasSingle: true}
	}
	m := make(map[T]empty, len(members))
	for _, member := range members {
		m[member] = empty{}
	}
	if len(m) == 1 {
		for k := range m {
			return Set[T]{single: k, hasSingle: true}
		}
	}
	return Set[T]{members: m}
}

// Has returns 'true' if 'member' is in the set.
func (s Set[T]) Has(member T) bool {
	if s.hasSingle {
		return s.single == member
	}
	_, ok := s.members[member]
	return ok
}

// Insert inserts a member to the set.
// Returns 'true' when '*s' value has changed,
// so that if it is stored by value the caller must knows to update the stored value.
func (s *Set[T]) Insert(member T) (changed bool) {
	if s.hasSingle {
		if member == s.single {
			return false
		}
		s.members = make(map[T]empty, 2)
		s.members[s.single] = empty{}
		var zero T
		s.single = zero
		s.hasSingle = false
		s.members[member] = empty{}
		return true
	}
	if s.members == nil {
		s.single = member
		s.hasSingle = true
		return true
	}
	if _, ok := s.members[member]; ok {
		return false
	}
	s.members[member] = empty{}
	return false
}

// Merge inserts members in 'o' into to the set 's'.
// Returns 'true' when '*s' value has changed,
// so that if it is stored by value the caller must knows to update the stored value.
func (s *Set[T]) Merge(sets ...Set[T]) (changed bool) {
	for _, other := range sets {
		for m := range other.Members() {
			changed = s.Insert(m) || changed
		}
	}
	return changed
}

// Remove removes a member from the set.
// Returns 'true' when '*s' value was changed, so that if it is stored by value the caller knows to
// update the stored value.
func (s *Set[T]) Remove(member T) (changed bool) {
	if s.hasSingle {
		if s.single == member {
			var zero T
			s.single = zero
			s.hasSingle = false
			return true
		}
		return false
	}
	if s.members == nil {
		return false
	}
	if _, ok := s.members[member]; !ok {
		return false
	}
	delete(s.members, member)
	if len(s.members) == 1 {
		for m := range s.members {
			s.single = m
		}
		s.hasSingle = true
		s.members = nil
		return true
	}
	return false
}

// RemoveSets removes one or more Sets from the receiver set.
// Returns 'true' when '*s' value was changed, so that if it is stored by value the caller knows to
// update the stored value.
func (s *Set[T]) RemoveSets(sets ...Set[T]) (changed bool) {
	for _, other := range sets {
		for m := range other.Members() {
			changed = s.Remove(m) || changed
		}
	}
	return changed
}

// Clear makes the set '*s' empty.
func (s *Set[T]) Clear() {
	var zero T
	s.single = zero
	s.hasSingle = false
	s.members = nil
}

// Equal returns 'true' if the receiver and argument sets are the same.
func (s Set[T]) Equal(o Set[T]) bool {
	sLen := s.Len()
	oLen := o.Len()

	if sLen != oLen {
		return false
	}

	switch sLen {
	case 0:
		return true
	case 1:
		return s.single == o.single
	}
	// compare the elements of the maps
	for member := range s.members {
		if _, ok := o.members[member]; !ok {
			return false
		}
	}
	return true
}

// DeepEqual is same as Equal due to Set keys being comparable.
func (s *Set[T]) DeepEqual(o *Set[T]) bool {
	return s.Equal(*o)
}

func (in *Set[T]) DeepCopyInto(out *Set[T]) {
	*out = *in
	if in.members != nil {
		out.members = maps.Clone(in.members)
	}
}

// Members returns an iterator for the members in the set.
func (s Set[T]) Members() iter.Seq[T] {
	return func(yield func(m T) bool) {
		if s.hasSingle {
			yield(s.single)
		} else {
			for member := range s.members {
				if !yield(member) {
					return
				}
			}
		}
	}
}

// MembersOfType return an iterator for each member of type M in the set.
func MembersOfType[M any, T comparable](s Set[T]) iter.Seq[M] {
	return func(yield func(m M) bool) {
		if s.hasSingle {
			if v, ok := any(s.single).(M); ok {
				yield(v)
			}
		} else {
			for m := range s.members {
				if v, ok := any(m).(M); ok {
					if !yield(v) {
						return
					}
				}
			}
		}
	}
}

// Get returns any one member from the set.
// Useful when it is known that the set has only one element.
func (s Set[T]) Get() (m T, found bool) {
	if s.hasSingle {
		return s.single, true
	}
	for m = range s.members {
		return m, true
	}
	var zero T
	return zero, false
}

// AsSlice converts the set to a slice.
func (s Set[T]) AsSlice() []T {
	if s.hasSingle {
		return []T{s.single}
	}
	if len(s.members) == 0 {
		return nil
	}
	res := make([]T, 0, len(s.members))
	for m := range s.members {
		res = append(res, m)
	}
	return res
}

// Clone returns a copy of the set.
func (s Set[T]) Clone() Set[T] {
	if s.members != nil {
		return Set[T]{members: maps.Clone(s.members)}
	}
	return s // singular value or empty Set
}
