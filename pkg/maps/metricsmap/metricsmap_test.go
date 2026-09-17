// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metricsmap

import (
	"log/slog"
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

type mockMap struct {
	entries []struct {
		key    Key
		values Values
	}
}

func (m *mockMap) IterateWithCallback(cb IterateCallback) error {
	for i := range m.entries {
		cb(&m.entries[i].key, &m.entries[i].values)
	}
	return nil
}

func (m *mockMap) Delete(k *Key) error {
	return nil
}

func newMockMetricsMap(n int) *mockMap {
	m := &mockMap{entries: make([]struct {
		key    Key
		values Values
	}, n)}
	for i := 0; i < n; i++ {
		m.entries[i].key = Key{
			Reason: uint8(130 + (i % 20)),
			Dir:    uint8((i % 4)),
			Line:   uint16(100 + i),
			File:   uint8(1 + (i % 10)),
		}
		m.entries[i].values = make(Values, 8)
		for c := 0; c < 8; c++ {
			m.entries[i].values[c] = Value{
				Count: uint64(10 + i + c),
				Bytes: uint64(1000 + i*100 + c*10),
			}
		}
	}
	return m
}

func TestMetricDirection(t *testing.T) {
	require.Equal(t, "UNKNOWN", MetricDirection(dirUnknown))
	require.Equal(t, "INGRESS", MetricDirection(dirIngress))
	require.Equal(t, "EGRESS", MetricDirection(dirEgress))
	require.Equal(t, "SERVICE", MetricDirection(dirService))
	require.Equal(t, "UNKNOWN", MetricDirection(99))
}

func TestValuesCountBytes(t *testing.T) {
	vs := Values{
		{Count: 10, Bytes: 100},
		{Count: 20, Bytes: 200},
		{Count: 30, Bytes: 300},
	}
	require.Equal(t, uint64(60), vs.Count())
	require.Equal(t, uint64(600), vs.Bytes())

	count, bytes := vs.Sum()
	require.Equal(t, uint64(60), count)
	require.Equal(t, uint64(600), bytes)
}

func BenchmarkMetricDirection(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = MetricDirection(dirIngress)
	}
}

func BenchmarkValues_CountAndBytes(b *testing.B) {
	vs := make(Values, 64)
	for i := range vs {
		vs[i] = Value{Count: uint64(i), Bytes: uint64(i * 100)}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = vs.Count()
		_ = vs.Bytes()
	}
}

func BenchmarkValues_Sum(b *testing.B) {
	vs := make(Values, 64)
	for i := range vs {
		vs[i] = Value{Count: uint64(i), Bytes: uint64(i * 100)}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = vs.Sum()
	}
}

func BenchmarkMetricsMap_Collect(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mock := newMockMetricsMap(256)
	collector := newMetricsMapCollector(logger, mock).(*metricsmapCollector)

	ch := make(chan prometheus.Metric, 2048)
	go func() {
		for range ch {
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.Collect(ch)
	}
}
