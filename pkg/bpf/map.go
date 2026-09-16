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

func isDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func trimVersionSuffix(str string) (string, bool) {
	idx := strings.LastIndex(str, "_v")
	if idx <= 0 {
		return str, false
	}
	vdigits := str[idx+2:]
	if !isDigits(vdigits) {
		return str, false
	}
	return str[:idx], true
}

func extractCommonName(name string) string {
	const prefix = "cilium_"
	if !strings.HasPrefix(name, prefix) {
		return name
	}
	s := name[len(prefix):]
	if len(s) == 0 {
		return name
	}

	lastUnderscore := strings.LastIndexByte(s, '_')
	if lastUnderscore <= 0 || !isDigits(s[lastUnderscore+1:]) {
		return s
	}

	beforeDigits := s[:lastUnderscore]

	// Check for _reserved (pattern 1: _v[0-9]+_reserved_[0-9]+ or pattern 2: _reserved_[0-9]+)
	if strings.HasSuffix(beforeDigits, "_reserved") {
		beforeReserved := strings.TrimSuffix(beforeDigits, "_reserved")
		if trimmed, ok := trimVersionSuffix(beforeReserved); ok && len(trimmed) > 0 {
			return trimmed
		}
		if len(beforeReserved) > 0 {
			return beforeReserved
		}
	}

	// Check for _netdev_ns (pattern 3: _netdev_ns_[0-9]+)
	if strings.HasSuffix(beforeDigits, "_netdev_ns") {
		beforeNetdev := strings.TrimSuffix(beforeDigits, "_netdev_ns")
		if len(beforeNetdev) > 0 {
			return beforeNetdev
		}
	}

	// Check for _overlay (pattern 4: _overlay_[0-9]+)
	if strings.HasSuffix(beforeDigits, "_overlay") {
		beforeOverlay := strings.TrimSuffix(beforeDigits, "_overlay")
		if len(beforeOverlay) > 0 {
			return beforeOverlay
		}
	}

	// Check for _v[0-9]+ (pattern 5: _v[0-9]+_[0-9]+)
	if trimmed, ok := trimVersionSuffix(beforeDigits); ok && len(trimmed) > 0 {
		return trimmed
	}

	// Pattern 6: _[0-9]+
	if len(beforeDigits) > 0 {
		return beforeDigits
	}

	// Pattern 7: any non-empty name
	return s
}
