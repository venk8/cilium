// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"
)

func BenchmarkDropReason_Known(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = DropReason(133)
	}
}

func BenchmarkDropReason_Unknown(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = DropReason(250)
	}
}

func BenchmarkDropReasonExt_KnownWithExt(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = DropReasonExt(133, -1)
	}
}

func BenchmarkBPFFileName_Known(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = BPFFileName(1)
	}
}

func BenchmarkBPFFileName_Unknown(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = BPFFileName(250)
	}
}

func BenchmarkTraceObservationPoint_Known(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = TraceObservationPoint(TraceToLxc)
	}
}

func BenchmarkMessageTypeName(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = MessageTypeName(MessageTypeDrop)
	}
}

func BenchmarkAllMessageTypeNames(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = AllMessageTypeNames()
	}
}

func BenchmarkAgentNotify_GetJSON(b *testing.B) {
	an := &AgentNotify{
		Type: AgentNotifyPolicyUpdated,
		Text: `{"labels":["key=val"],"revision":1,"rule_count":1}`,
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = an.getJSON()
	}
}
