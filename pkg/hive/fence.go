// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"golang.org/x/sync/semaphore"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Fence is an utility for blocking until registered wait functions have completed.
//
// The wait functions can only be Add()'d' before Hive is started, e.g. from constructors
// or invoke functions. Conversely Wait() method can only be called during/after Hive start.
type Fence interface {
	// Add a named wait function to the fence.
	// The provided function should block until ready or until context has been
	// cancelled. It should return [context.Err] if context is cancelled.
	//
	// This method will panic if called after Hive has started to ensure that when
	// Wait() is called all initializers have already been registered.
	Add(name string, waitFn WaitFunc)

	// Wait blocks until all registered initializers have completed or until
	// context has cancelled.
	//
	// This method will panic if called before Hive is started.
	// Can be called any number of times.
	Wait(ctx context.Context) error
}

// NewFence constructs a new [Fence].
func NewFence(lc cell.Lifecycle, log *slog.Logger) Fence {
	iwg := &fence{
		mu:        newContextMutex(),
		log:       log,
		waitFuncs: map[string]WaitFunc{},
	}
	lc.Append(cell.Hook{
		OnStart: iwg.Start,
	})
	return iwg
}

// WaitFunc is a function for waiting until some initialization has completed.
// If the context given to it is cancelled the function should stop and return ctx.Err().
type WaitFunc = func(context.Context) error

const nameLogField = "name"

type fence struct {
	mu        contextMutex
	log       *slog.Logger
	started   bool
	waitFuncs map[string]WaitFunc
}

func (w *fence) Add(name string, waitFn WaitFunc) {
	// Add calls must happen sequentially during Hive population so no context here.
	w.mu.Lock(context.Background())
	defer w.mu.Unlock()

	if w.started {
		panic("Add() called after Hive had already started! Add() must be used from provide/invoke functions.")
	}
	if _, found := w.waitFuncs[name]; found {
		panic(fmt.Sprintf("%s already registered", name))
	}
	w.waitFuncs[name] = waitFn
}

func (w *fence) Wait(ctx context.Context) error {
	if err := w.mu.Lock(ctx); err != nil {
		return err
	}
	defer w.mu.Unlock()

	if !w.started {
		panic("Wait() called before Hive had already started! Wait() must be called during start to ensure all Add() calls have happened.")
	}

	if len(w.waitFuncs) == 0 {
		return nil
	}

	remaining := len(w.waitFuncs)
	for name, fn := range w.waitFuncs {
		t0 := time.Now()
		attrName := slog.String(nameLogField, name)
		attrRemaining := slog.Int(logfields.Remaining, remaining)
		w.log.LogAttrs(ctx, slog.LevelInfo, "Fence waiting",
			attrName,
			attrRemaining,
		)
		if err := fn(ctx); err != nil {
			w.log.LogAttrs(ctx, slog.LevelInfo, "Fence error",
				attrName,
				attrRemaining,
				slog.Any(logfields.Error, err),
			)
			return fmt.Errorf("%s: %w", name, err)
		}
		w.log.LogAttrs(ctx, slog.LevelInfo, "Fence done",
			attrName,
			attrRemaining,
			slog.Duration(logfields.Duration, time.Since(t0)),
		)
		remaining--
		delete(w.waitFuncs, name)
	}

	return nil
}

func (w *fence) Start(ctx cell.HookContext) error {
	if err := w.mu.Lock(ctx); err != nil {
		return err
	}
	defer w.mu.Unlock()
	w.started = true
	return nil
}

type contextMutex struct {
	sem *semaphore.Weighted
}

func newContextMutex() contextMutex {
	return contextMutex{sem: semaphore.NewWeighted(1)}
}

func (c *contextMutex) Lock(ctx context.Context) error {
	return c.sem.Acquire(ctx, 1)
}

func (c *contextMutex) Unlock() {
	c.sem.Release(1)
}
