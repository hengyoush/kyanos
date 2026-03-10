package common

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// GoroutineManager helps manage goroutines with proper cleanup
type GoroutineManager struct {
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
	errors  chan error
	stopped bool
	mu      sync.Mutex
}

// NewGoroutineManager creates a new goroutine manager
func NewGoroutineManager(parentCtx context.Context) *GoroutineManager {
	ctx, cancel := context.WithCancel(parentCtx)
	return &GoroutineManager{
		ctx:    ctx,
		cancel: cancel,
		errors: make(chan error, 100),
	}
}

// Context returns the managed context
func (gm *GoroutineManager) Context() context.Context {
	return gm.ctx
}

// Go starts a goroutine with panic recovery and proper cleanup
func (gm *GoroutineManager) Go(name string, fn func(ctx context.Context) error) {
	gm.mu.Lock()
	if gm.stopped {
		gm.mu.Unlock()
		return
	}
	gm.wg.Add(1)
	gm.mu.Unlock()

	go func() {
		defer gm.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				err := fmt.Errorf("goroutine %s panic: %v\n%s", name, r, buf[:n])
				AgentLog.Errorf("%v", err)
				select {
				case gm.errors <- err:
				default:
				}
			}
		}()

		if err := fn(gm.ctx); err != nil && err != context.Canceled {
			AgentLog.Warnf("goroutine %s error: %v", name, err)
			select {
			case gm.errors <- err:
			default:
			}
		}
	}()
}

// Stop stops all managed goroutines and waits for them to finish
func (gm *GoroutineManager) Stop(timeoutMs int) {
	gm.mu.Lock()
	gm.stopped = true
	gm.mu.Unlock()

	gm.cancel()

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		gm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
		AgentLog.Warnf("goroutine manager stop timeout, some goroutines may still be running")
	}
}

// Errors returns the error channel
func (gm *GoroutineManager) Errors() <-chan error {
	return gm.errors
}

// SafeGo starts a goroutine with panic recovery (simple version)
func SafeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				AgentLog.Errorf("goroutine %s panic: %v\n%s", name, r, buf[:n])
			}
		}()
		fn()
	}()
}
