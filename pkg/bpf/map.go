// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"strings"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// maxSyncErrors is the maximum consecutive errors syncing before the
	// controller bails out
	maxSyncErrors = 512

	// errorResolverSchedulerMinInterval is the minimum interval for the
	// error resolver to be scheduled. This minimum interval ensures not to
	// overschedule if a large number of updates fail in a row.
	errorResolverSchedulerMinInterval = 5 * time.Second

	// errorResolverSchedulerDelay is the delay to update the controller
	// after determination that a run is needed. The delay allows to
	// schedule the resolver after series of updates have failed.
	errorResolverSchedulerDelay = 200 * time.Millisecond
)

var (
	mapControllers = controller.NewManager()
)

// DesiredAction is the action to be performed on the BPF map
type DesiredAction uint8

const (
	// OK indicates that to further action is required and the entry is in
	// sync
	OK DesiredAction = iota

	// Insert indicates that the entry needs to be created or updated
	Insert

	// Delete indicates that the entry needs to be deleted
	Delete
)

func (d DesiredAction) String() string {
	switch d {
	case OK:
		return "sync"
	case Insert:
		return "to-be-inserted"
	case Delete:
		return "to-be-deleted"
	default:
		return "unknown"
	}
}

func extractCommonName(name string) string {
	s := strings.TrimPrefix(name, "cilium_")
	if s == name || len(s) == 0 {
		return name
	}

	p, ok := trimDigitsSuffix(s)
	if !ok {
		return s
	}

	const reservedSuffix = "_reserved"
	if strings.HasSuffix(p, reservedSuffix) {
		rem := p[:len(p)-len(reservedSuffix)]
		if len(rem) > 0 {
			if v, ok := trimVersionSuffix(rem); ok {
				return v
			}
			return rem
		}
	}

	const netdevSuffix = "_netdev_ns"
	if strings.HasSuffix(p, netdevSuffix) {
		rem := p[:len(p)-len(netdevSuffix)]
		if len(rem) > 0 {
			return rem
		}
	}

	const overlaySuffix = "_overlay"
	if strings.HasSuffix(p, overlaySuffix) {
		rem := p[:len(p)-len(overlaySuffix)]
		if len(rem) > 0 {
			return rem
		}
	}

	if v, ok := trimVersionSuffix(p); ok {
		return v
	}

	return p
}

func trimDigitsSuffix(s string) (string, bool) {
	i := len(s) - 1
	for i >= 0 && s[i] >= '0' && s[i] <= '9' {
		i--
	}
	if i >= 1 && i < len(s)-1 && s[i] == '_' {
		return s[:i], true
	}
	return s, false
}

func trimVersionSuffix(s string) (string, bool) {
	i := len(s) - 1
	for i >= 0 && s[i] >= '0' && s[i] <= '9' {
		i--
	}
	if i >= 2 && i < len(s)-1 && s[i] == 'v' && s[i-1] == '_' {
		return s[:i-1], true
	}
	return s, false
}
