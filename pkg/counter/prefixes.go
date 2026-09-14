// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package counter

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/lock"
)

// PrefixLengthCounter tracks references to prefix lengths, limited by the
// maxUniquePrefixes count. Neither of the IPv4 or IPv6 counters nested within
// may contain more keys than the specified maximum number of unique prefixes.
type PrefixLengthCounter struct {
	lock.RWMutex

	v4 IntCounter
	v6 IntCounter

	s4 []int
	s6 []int

	maxUniquePrefixes4 int
	maxUniquePrefixes6 int
}

// NewPrefixLengthCounter returns a new PrefixLengthCounter which limits
// insertions to the specified maximum number of unique prefix lengths.
func NewPrefixLengthCounter(maxUniquePrefixes6, maxUniquePrefixes4 int) *PrefixLengthCounter {
	return &PrefixLengthCounter{
		v4:                 make(IntCounter),
		v6:                 make(IntCounter),
		s4:                 []int{},
		s6:                 []int{},
		maxUniquePrefixes4: maxUniquePrefixes4,
		maxUniquePrefixes6: maxUniquePrefixes6,
	}
}

func createIPNet(ones, bits int) netip.Prefix {
	var addr netip.Addr
	switch bits {
	case net.IPv4len * 8:
		addr = netip.IPv4Unspecified()
	case net.IPv6len * 8:
		addr = netip.IPv6Unspecified()
	default:
		// fall through to default library error
	}
	return netip.PrefixFrom(addr, ones)
}

// DefaultPrefixLengthCounter creates a default prefix length counter that
// already counts the minimum and maximum prefix lengths for IP hosts and
// default routes (ie, /32 and /0). As with NewPrefixLengthCounter, insertions
// are limited to the specified maximum number of unique prefix lengths.
func DefaultPrefixLengthCounter() *PrefixLengthCounter {
	maxIPv4 := net.IPv4len*8 + 1
	maxIPv6 := net.IPv6len*8 + 1
	counter := NewPrefixLengthCounter(maxIPv6, maxIPv4)

	defaultPrefixes := []netip.Prefix{
		// IPv4
		createIPNet(0, net.IPv4len*8),             // world
		createIPNet(net.IPv4len*8, net.IPv4len*8), // hosts

		// IPv6
		createIPNet(0, net.IPv6len*8),             // world
		createIPNet(net.IPv6len*8, net.IPv6len*8), // hosts
	}
	if _, err := counter.Add(defaultPrefixes); err != nil {
		panic(fmt.Errorf("Failed to create default prefix lengths: %w", err))
	}

	return counter
}

// checkLimits checks whether the specified new count of prefixes would exceed
// the specified limit on the maximum number of unique keys, and returns an
// error if it would exceed the limit.
func checkLimits(current, newCount, max int) error {
	if newCount > max {
		return fmt.Errorf("adding specified prefixes would result in too many prefix lengths (current: %d, result: %d, max: %d)",
			current, newCount, max)
	}
	return nil
}

// Add increments references to prefix lengths for the specified IPNets to the
// counter. If the maximum number of unique prefix lengths would be exceeded,
// returns an error.
//
// Returns true if adding these prefixes results in an increase in the total
// number of unique prefix lengths in the counter.
func (p *PrefixLengthCounter) Add(prefixes []netip.Prefix) (bool, error) {
	p.Lock()
	defer p.Unlock()

	if len(prefixes) == 1 {
		return p.addPrefixLocked(prefixes[0])
	}

	// Assemble a map of references that need to be added
	newV4Counter := p.v4.DeepCopy()
	newV6Counter := p.v6.DeepCopy()
	newV4Prefixes := false
	newV6Prefixes := false
	for _, prefix := range prefixes {
		ones := prefix.Bits()
		bits := prefix.Addr().BitLen()

		switch bits {
		case net.IPv4len * 8:
			if newV4Counter.Add(ones) {
				newV4Prefixes = true
			}
		case net.IPv6len * 8:
			if newV6Counter.Add(ones) {
				newV6Prefixes = true
			}
		default:
			return false, fmt.Errorf("unsupported IPAddr bitlength %d", bits)
		}
	}

	// Check if they can be added given the limit in place
	if newV4Prefixes {
		if err := checkLimits(len(p.v4), len(newV4Counter), p.maxUniquePrefixes4); err != nil {
			return false, err
		}
	}
	if newV6Prefixes {
		if err := checkLimits(len(p.v6), len(newV6Counter), p.maxUniquePrefixes6); err != nil {
			return false, err
		}
	}

	// Set and return whether anything changed
	p.v4 = newV4Counter
	p.v6 = newV6Counter
	if newV4Prefixes {
		p.s4 = p.v4.ToBPFData()
	}
	if newV6Prefixes {
		p.s6 = p.v6.ToBPFData()
	}
	return newV4Prefixes || newV6Prefixes, nil
}

// AddPrefix increments references to a single prefix length for the specified netip.Prefix.
// Returns true if adding this prefix results in a new unique prefix length.
func (p *PrefixLengthCounter) AddPrefix(prefix netip.Prefix) (bool, error) {
	p.Lock()
	defer p.Unlock()

	return p.addPrefixLocked(prefix)
}

func (p *PrefixLengthCounter) addPrefixLocked(prefix netip.Prefix) (bool, error) {
	ones := prefix.Bits()
	bits := prefix.Addr().BitLen()

	switch bits {
	case net.IPv4len * 8:
		if p.v4.Has(ones) {
			p.v4.Add(ones)
			return false, nil
		}
		if err := checkLimits(len(p.v4), len(p.v4)+1, p.maxUniquePrefixes4); err != nil {
			return false, err
		}
		p.v4.Add(ones)
		p.s4 = p.v4.ToBPFData()
		return true, nil
	case net.IPv6len * 8:
		if p.v6.Has(ones) {
			p.v6.Add(ones)
			return false, nil
		}
		if err := checkLimits(len(p.v6), len(p.v6)+1, p.maxUniquePrefixes6); err != nil {
			return false, err
		}
		p.v6.Add(ones)
		p.s6 = p.v6.ToBPFData()
		return true, nil
	default:
		return false, fmt.Errorf("unsupported IPAddr bitlength %d", bits)
	}
}

// Delete reduces references to prefix lengths in the specified IPNets from
// the counter. Returns true if removing references to these prefix lengths
// would result in a decrese in the total number of unique prefix lengths in
// the counter.
func (p *PrefixLengthCounter) Delete(prefixes []netip.Prefix) (changed bool) {
	p.Lock()
	defer p.Unlock()

	if len(prefixes) == 1 {
		return p.deletePrefixLocked(prefixes[0])
	}

	var v4Changed, v6Changed bool
	for _, prefix := range prefixes {
		ones := prefix.Bits()
		bits := prefix.Addr().BitLen()
		switch bits {
		case net.IPv4len * 8:
			if p.v4.Delete(ones) {
				v4Changed = true
			}
		case net.IPv6len * 8:
			if p.v6.Delete(ones) {
				v6Changed = true
			}
		}
	}

	if v4Changed {
		p.s4 = p.v4.ToBPFData()
	}
	if v6Changed {
		p.s6 = p.v6.ToBPFData()
	}

	return v4Changed || v6Changed
}

// DeletePrefix decrements references to a single prefix length for the specified netip.Prefix.
// Returns true if removing references results in a decrease in the total number of unique prefix lengths.
func (p *PrefixLengthCounter) DeletePrefix(prefix netip.Prefix) bool {
	p.Lock()
	defer p.Unlock()

	return p.deletePrefixLocked(prefix)
}

func (p *PrefixLengthCounter) deletePrefixLocked(prefix netip.Prefix) bool {
	ones := prefix.Bits()
	bits := prefix.Addr().BitLen()

	switch bits {
	case net.IPv4len * 8:
		if p.v4.Delete(ones) {
			p.s4 = p.v4.ToBPFData()
			return true
		}
		return false
	case net.IPv6len * 8:
		if p.v6.Delete(ones) {
			p.s6 = p.v6.ToBPFData()
			return true
		}
		return false
	default:
		return false
	}
}

// ToBPFData converts the counter into a set of prefix lengths that the BPF
// datapath can use for LPM lookup.
func (p *PrefixLengthCounter) ToBPFData() (s6, s4 []int) {
	p.RLock()
	defer p.RUnlock()

	return p.s6, p.s4
}
