// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "strings"

// RegisterResourceIDParser is a deprecated no-op hook retained for backward API
// compatibility. Resource ID parsing is performed natively without external
// SDK dependencies.
func RegisterResourceIDParser(_ func(id string) (resourceGroup, vmssName, vmID string)) {
}

func parseAzureResourceID(id string) (resourceGroup, vmssName, vmID string) {
	if len(id) == 0 || id[0] != '/' {
		return "", "", ""
	}

	var (
		hasKey     bool
		currentKey string
		pairCount  int
		rg         string
		vmss       string
		vm         string
	)

	pos := 1
	for pos < len(id) {
		var seg string
		nextSlash := strings.IndexByte(id[pos:], '/')
		if nextSlash == -1 {
			seg = id[pos:]
			pos = len(id)
		} else {
			seg = id[pos : pos+nextSlash]
			pos += nextSlash + 1
		}

		seg = strings.TrimSpace(seg)
		if len(seg) == 0 {
			continue
		}

		if !hasKey {
			if pairCount == 0 {
				if !strings.EqualFold(seg, "subscriptions") && !strings.EqualFold(seg, "providers") {
					return "", "", ""
				}
			}
			currentKey = seg
			hasKey = true
		} else {
			switch {
			case strings.EqualFold(currentKey, "resourceGroups"):
				rg = seg
			case strings.EqualFold(currentKey, "virtualMachineScaleSets"):
				vmss = seg
			case strings.EqualFold(currentKey, "virtualMachines"):
				vm = seg
			}
			hasKey = false
			pairCount++
		}
	}

	if hasKey || pairCount == 0 {
		return "", "", ""
	}

	return rg, vmss, vm
}
