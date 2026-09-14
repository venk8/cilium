// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"iter"

	"github.com/cilium/cilium/api/v1/models"
	loaderMetrics "github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/time"
)

var endpointPolicyStatus endpointPolicyStatusMap

func init() {
	endpointPolicyStatus = newEndpointPolicyStatusMap()
}

type statistics interface {
	GetMap() map[string]*spanstat.SpanStat
}

func sendMetrics(stats *regenerationStatistics, metric metric.Vec[metric.Observer]) {
	for scope, stat := range stats.All() {
		// Skip scopes that have not been hit (zero duration), so the count in
		// the histogram accurately reflects the number of times each scope is
		// hit, and the distribution is not incorrectly skewed towards zero.
		if stat.SuccessTotal() != time.Duration(0) {
			metric.WithLabelValues(scope, "success").Observe(stat.SuccessTotal().Seconds())
		}
		if stat.FailureTotal() != time.Duration(0) {
			metric.WithLabelValues(scope, "failure").Observe(stat.FailureTotal().Seconds())
		}
	}
}

type regenerationStatistics struct {
	regenReason        regeneration.Reason
	regenFailureReason regenerationFailureReason

	success      bool
	endpointID   uint16
	policyStatus models.EndpointPolicyEnabled

	buildPermitAcquisition    spanstat.SpanStat
	totalTime                 spanstat.SpanStat
	waitingForLock            spanstat.SpanStat
	waitingForCTClean         spanstat.SpanStat
	policyCalculation         spanstat.SpanStat
	waitForPolicyCompute      spanstat.SpanStat
	endpointPolicyCalculation spanstat.SpanStat
	proxyConfiguration        spanstat.SpanStat
	proxyPolicyCalculation    spanstat.SpanStat
	proxyWaitForAck           spanstat.SpanStat
	datapathRealization       loaderMetrics.SpanStat
	mapSync                   spanstat.SpanStat
	prepareBuild              spanstat.SpanStat
	// policyDetachedTimestamp tracks the time the selector policy of the endpoint was detached.
	// This is nil if the selector policy was still attached when the operation (policy update or endpoint regeneration)
	// started
	policyDetachedTimestamp *time.Time
	// Reflects the number of proxy redirects that were expected but not programmed during regeneration.
	missingProxyRedirectsCount uint
}

// SendMetrics sends the regeneration statistics for this endpoint to
// Prometheus.
func (s *regenerationStatistics) SendMetrics() {
	endpointPolicyStatus.Update(s.endpointID, s.policyStatus, s.missingProxyRedirectsCount)

	if s.policyDetachedTimestamp != nil {
		metrics.EndpointDetachedSelectorPolicyTimeStats.WithLabelValues("regeneration").Observe(time.Since(*s.policyDetachedTimestamp).Seconds())
	}

	if !s.success {
		// Endpoint regeneration failed, increase on failed metrics
		metrics.EndpointRegenerationTotal.WithLabelValues(s.regenReason, metrics.LabelValueOutcomeFail, s.regenFailureReason.String()).Inc()
		return
	}

	metrics.EndpointRegenerationTotal.WithLabelValues(s.regenReason, metrics.LabelValueOutcomeSuccess, s.regenFailureReason.String()).Inc()

	sendMetrics(s, metrics.EndpointRegenerationTimeStats)
}

// All yields each statistic name and its SpanStat.
func (s *regenerationStatistics) All() iter.Seq2[string, *spanstat.SpanStat] {
	return func(yield func(string, *spanstat.SpanStat) bool) {
		if !yield("waitingForLock", &s.waitingForLock) ||
			!yield("waitingForCTClean", &s.waitingForCTClean) ||
			!yield("policyCalculation", &s.policyCalculation) ||
			!yield("proxyConfiguration", &s.proxyConfiguration) ||
			!yield("waitForPolicyCompute", &s.waitForPolicyCompute) ||
			!yield("endpointPolicyCalculation", &s.endpointPolicyCalculation) ||
			!yield("proxyPolicyCalculation", &s.proxyPolicyCalculation) ||
			!yield("proxyWaitForAck", &s.proxyWaitForAck) ||
			!yield("mapSync", &s.mapSync) ||
			!yield("prepareBuild", &s.prepareBuild) ||
			!yield("total", &s.totalTime) ||
			!yield("buildPermitAcquisition", &s.buildPermitAcquisition) {
			return
		}
		for field, stat := range s.datapathRealization.GetMap() {
			if !yield(field, stat) {
				return
			}
		}
	}
}

// GetMap returns a map which key is the stat name and the value is the stat
func (s *regenerationStatistics) GetMap() map[string]*spanstat.SpanStat {
	result := make(map[string]*spanstat.SpanStat, 15)
	for field, stat := range s.All() {
		result[field] = stat
	}
	return result
}

// endpointPolicyStatusMap is a map to store the endpoint id and the policy
// enforcement status. It is used only to send metrics to prometheus.
type endpointPolicyStatusMap struct {
	mutex lock.Mutex
	m     map[uint16]epPolicyStatus
}

type epPolicyStatus struct {
	enforcementStatus     models.EndpointPolicyEnabled
	missingRedirectsCount uint
}

func newEndpointPolicyStatusMap() endpointPolicyStatusMap {
	return endpointPolicyStatusMap{m: make(map[uint16]epPolicyStatus)}
}

// Update adds or updates a new endpoint to the map and update the metrics
// related
func (epPolicyMaps *endpointPolicyStatusMap) Update(endpointID uint16, enforcementStatus models.EndpointPolicyEnabled, missingRedirectsCount uint) {
	epPolicyMaps.mutex.Lock()
	epPolicyMaps.m[endpointID] = epPolicyStatus{
		enforcementStatus:     enforcementStatus,
		missingRedirectsCount: missingRedirectsCount,
	}
	epPolicyMaps.mutex.Unlock()
	endpointPolicyStatus.UpdateMetrics()
}

// Remove deletes the given endpoint from the map and update the metrics
func (epPolicyMaps *endpointPolicyStatusMap) Remove(endpointID uint16) {
	epPolicyMaps.mutex.Lock()
	delete(epPolicyMaps.m, endpointID)
	epPolicyMaps.mutex.Unlock()
	epPolicyMaps.UpdateMetrics()
}

// UpdateMetrics update the policy enforcement metrics statistics for the endpoints.
func (epPolicyMaps *endpointPolicyStatusMap) UpdateMetrics() {
	var (
		totalMissingRedirects uint
		countNone             float64
		countEgress           float64
		countIngress          float64
		countBoth             float64
		countAuditEgress      float64
		countAuditIngress     float64
		countAuditBoth        float64
	)

	epPolicyMaps.mutex.Lock()
	for _, value := range epPolicyMaps.m {
		switch value.enforcementStatus {
		case models.EndpointPolicyEnabledNone:
			countNone++
		case models.EndpointPolicyEnabledEgress:
			countEgress++
		case models.EndpointPolicyEnabledIngress:
			countIngress++
		case models.EndpointPolicyEnabledBoth:
			countBoth++
		case models.EndpointPolicyEnabledAuditDashEgress:
			countAuditEgress++
		case models.EndpointPolicyEnabledAuditDashIngress:
			countAuditIngress++
		case models.EndpointPolicyEnabledAuditDashBoth:
			countAuditBoth++
		}
		totalMissingRedirects += value.missingRedirectsCount
	}
	epPolicyMaps.mutex.Unlock()

	metrics.PolicyEndpointStatus.WithLabelValues(string(models.EndpointPolicyEnabledNone)).Set(countNone)
	metrics.PolicyEndpointStatus.WithLabelValues(string(models.EndpointPolicyEnabledEgress)).Set(countEgress)
	metrics.PolicyEndpointStatus.WithLabelValues(string(models.EndpointPolicyEnabledIngress)).Set(countIngress)
	metrics.PolicyEndpointStatus.WithLabelValues(string(models.EndpointPolicyEnabledBoth)).Set(countBoth)
	metrics.PolicyEndpointStatus.WithLabelValues(string(models.EndpointPolicyEnabledAuditDashEgress)).Set(countAuditEgress)
	metrics.PolicyEndpointStatus.WithLabelValues(string(models.EndpointPolicyEnabledAuditDashIngress)).Set(countAuditIngress)
	metrics.PolicyEndpointStatus.WithLabelValues(string(models.EndpointPolicyEnabledAuditDashBoth)).Set(countAuditBoth)
	metrics.PolicyMissingProxyRedirects.WithLabelValues().Set(float64(totalMissingRedirects))
}
