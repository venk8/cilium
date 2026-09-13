// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"log/slog"
	"sync"

	"google.golang.org/protobuf/proto"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	fa "github.com/cilium/cilium/pkg/hubble/parser/fieldaggregate"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// AggregateKey represents a combination of field values used for aggregation.
type AggregateKey string

// AggregateValue holds the counters for ingress, egress, and unknown direction flows.
type AggregateValue struct {
	IngressFlowCount          int
	EgressFlowCount           int
	UnknownDirectionFlowCount int
	ProcessedFlow             *flowpb.Flow
}

type Aggregator struct {
	m              map[AggregateKey]*AggregateValue
	mu             lock.RWMutex
	fieldAggregate fa.FieldAggregate
	logger         *slog.Logger
	scratchFlow    flowpb.Flow
	scratchBuf     []byte
}

// NewAggregator creates a new aggregator without field aggregation.
func NewAggregator(logger *slog.Logger) *Aggregator {
	return &Aggregator{
		m:          make(map[AggregateKey]*AggregateValue),
		logger:     logger.With(logfields.LogSubsys, "hubble-aggregator"),
		scratchBuf: make([]byte, 0, 256),
	}
}

// NewAggregatorWithFields creates a new aggregator with field aggregation.
func NewAggregatorWithFields(fieldAggregate fa.FieldAggregate, logger *slog.Logger) *Aggregator {
	return &Aggregator{
		m:              make(map[AggregateKey]*AggregateValue),
		fieldAggregate: fieldAggregate,
		logger:         logger.With(logfields.LogSubsys, "hubble-aggregator"),
		scratchBuf:     make([]byte, 0, 256),
	}
}

func (a *Aggregator) Add(ev *v1.Event) {
	f := ev.GetFlow()
	if f == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.scratchFlow.Reset()
	a.fieldAggregate.Copy(a.scratchFlow.ProtoReflect(), f.ProtoReflect())

	a.scratchBuf = a.scratchBuf[:0]
	var err error
	a.scratchBuf, err = proto.MarshalOptions{}.MarshalAppend(a.scratchBuf, &a.scratchFlow)
	if err != nil {
		return
	}

	v, ok := a.m[AggregateKey(a.scratchBuf)]
	if !ok {
		processedFlow := proto.Clone(&a.scratchFlow).(*flowpb.Flow)
		processedFlow.Time = f.GetTime()
		switch f.GetTrafficDirection() {
		case flowpb.TrafficDirection_INGRESS:
			v = &AggregateValue{
				IngressFlowCount: 1,
				ProcessedFlow:    processedFlow,
			}
		case flowpb.TrafficDirection_EGRESS:
			v = &AggregateValue{
				EgressFlowCount: 1,
				ProcessedFlow:   processedFlow,
			}
		default:
			v = &AggregateValue{
				UnknownDirectionFlowCount: 1,
				ProcessedFlow:             processedFlow,
			}
		}
		a.m[AggregateKey(string(a.scratchBuf))] = v
	} else {
		switch f.GetTrafficDirection() {
		case flowpb.TrafficDirection_INGRESS:
			v.IngressFlowCount++
		case flowpb.TrafficDirection_EGRESS:
			v.EgressFlowCount++
		default:
			v.UnknownDirectionFlowCount++
		}
	}
}

// Export exports all aggregated flows and clears the aggregator.
func (a *Aggregator) Export(encoder Encoder) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, value := range a.m {
		exportEvent := processedFlowToAggregatedExportEvent(value.ProcessedFlow, value.IngressFlowCount, value.EgressFlowCount, value.UnknownDirectionFlowCount)
		if exportEvent == nil {
			continue
		}

		if err := encoder.Encode(exportEvent); err != nil {
			a.logger.Error("Failed to export aggregate", logfields.Error, err)
		}
	}

	clear(a.m)
}

func generateAggregationKey(processedFlow *flowpb.Flow) AggregateKey {
	b, _ := proto.Marshal(processedFlow)
	return AggregateKey(b)
}

// AggregatorRunner manages the lifecycle of an aggregator with periodic export.
type AggregatorRunner struct {
	aggregator *Aggregator
	interval   time.Duration
	encoder    Encoder
	logger     *slog.Logger

	stop chan struct{}
	wg   sync.WaitGroup
}

func (r *AggregatorRunner) Start() {
	if r.stop != nil {
		r.logger.Error("AggregatorRunner is already started.")
		return
	}
	r.stop = make(chan struct{})
	r.wg.Add(1)
	go r.run()
}

func (r *AggregatorRunner) Stop() {
	if r.stop != nil {
		close(r.stop)
	}
	r.wg.Wait()
	r.stop = nil
}

func (r *AggregatorRunner) Add(event *v1.Event) {
	r.aggregator.Add(event)
}

func (r *AggregatorRunner) run() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.interval)

	for {
		select {
		case <-r.stop:
			// Flush before stopping.
			r.exportAggregates()
			return
		case <-ticker.C:
			r.exportAggregates()
		}
	}
}

func (r *AggregatorRunner) exportAggregates() {
	r.aggregator.Export(r.encoder)
}

// processedFlowToAggregatedExportEvent converts a flow to ExportEvent with aggregation counts.
func processedFlowToAggregatedExportEvent(processedFlow *flowpb.Flow, ingressCount, egressCount, unknownDirectionFlowCount int) *observerpb.ExportEvent {
	aggregate := &flowpb.Aggregate{
		IngressFlowCount:          uint32(ingressCount),
		EgressFlowCount:           uint32(egressCount),
		UnknownDirectionFlowCount: uint32(unknownDirectionFlowCount),
	}

	processedFlow.Aggregate = aggregate

	return &observerpb.ExportEvent{
		Time:     processedFlow.GetTime(),
		NodeName: processedFlow.GetNodeName(),
		ResponseTypes: &observerpb.ExportEvent_Flow{
			Flow: processedFlow,
		},
	}
}
