// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spanstat

import (
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/safetime"
	"github.com/cilium/cilium/pkg/time"
)

// SpanStat measures the total duration of all time spent in between Start()
// and Stop() calls.
type SpanStat struct {
	mutex           lock.RWMutex
	spanStart       time.Time
	successDuration time.Duration
	failureDuration time.Duration
}

// Start creates a new SpanStat and starts it
func Start() *SpanStat {
	return &SpanStat{
		spanStart: time.Now(),
	}
}

// Start starts a new span
func (s *SpanStat) Start() *SpanStat {
	s.mutex.Lock()
	s.spanStart = time.Now()
	s.mutex.Unlock()
	return s
}

// EndError calls End() based on the value of err
func (s *SpanStat) EndError(err error) *SpanStat {
	s.mutex.Lock()
	s.end(err == nil)
	s.mutex.Unlock()
	return s
}

// End ends the current span and adds the measured duration to the total
// cumulated duration, and to the success or failure cumulated duration
// depending on the given success flag
func (s *SpanStat) End(success bool) *SpanStat {
	s.mutex.Lock()
	s.end(success)
	s.mutex.Unlock()
	return s
}

// EndTotal ends the current span and returns the total duration under a single lock acquisition.
func (s *SpanStat) EndTotal(success bool) time.Duration {
	s.mutex.Lock()
	s.end(success)
	d := s.successDuration + s.failureDuration
	s.mutex.Unlock()
	return d
}

// EndErrorTotal calls EndTotal based on the value of err.
func (s *SpanStat) EndErrorTotal(err error) time.Duration {
	return s.EndTotal(err == nil)
}

// must be called with Lock() held
func (s *SpanStat) end(success bool) *SpanStat {
	if !s.spanStart.IsZero() {
		// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
		d, _ := safetime.TimeSinceSafe(s.spanStart, logging.DefaultSlogLogger)
		if success {
			s.successDuration += d
		} else {
			s.failureDuration += d
		}
		s.spanStart = time.Time{}
	}
	return s
}

// Total returns the total duration of all spans measured, including both
// successes and failures
func (s *SpanStat) Total() time.Duration {
	s.mutex.RLock()
	d := s.successDuration + s.failureDuration
	s.mutex.RUnlock()
	return d
}

// SuccessTotal returns the total duration of all successful spans measured
func (s *SpanStat) SuccessTotal() time.Duration {
	s.mutex.RLock()
	d := s.successDuration
	s.mutex.RUnlock()
	return d
}

// FailureTotal returns the total duration of all unsuccessful spans measured
func (s *SpanStat) FailureTotal() time.Duration {
	s.mutex.RLock()
	d := s.failureDuration
	s.mutex.RUnlock()
	return d
}

// Reset rests the duration measurements
func (s *SpanStat) Reset() {
	s.mutex.Lock()
	s.successDuration = 0
	s.failureDuration = 0
	s.mutex.Unlock()
}

// Seconds returns the number of seconds represents by the spanstat. If a span
// is still open, it is closed first.
func (s *SpanStat) Seconds() float64 {
	s.mutex.Lock()
	if !s.spanStart.IsZero() {
		s.end(true)
	}

	total := s.successDuration + s.failureDuration
	s.mutex.Unlock()
	return total.Seconds()
}

// SetSuccessDuration sets the success duration of the SpanStat directly.
// This is useful for reconstructing timing data received from an external source
// (e.g., the standalone DNS proxy sending timing data via gRPC).
func (s *SpanStat) SetSuccessDuration(d time.Duration) {
	s.mutex.Lock()
	s.successDuration = d
	s.mutex.Unlock()
}
