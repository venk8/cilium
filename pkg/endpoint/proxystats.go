// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"cmp"
	"slices"

	"github.com/cilium/cilium/api/v1/models"
)

// sortProxyStats sorts the given slice of ProxyStatistics.
func sortProxyStats(proxyStats []*models.ProxyStatistics) {
	slices.SortFunc(proxyStats, func(s1, s2 *models.ProxyStatistics) int {
		return cmp.Or(
			cmp.Compare(s1.Port, s2.Port),
			cmp.Compare(s1.Location, s2.Location),
			cmp.Compare(s1.Protocol, s2.Protocol),
			cmp.Compare(s1.AllocatedProxyPort, s2.AllocatedProxyPort),
		)
	})
}
