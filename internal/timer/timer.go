// Copyright (C) 2025 Jan Wrobel <jan@wwwhisper.io>
// This program is freely distributable under the terms of the
// Simplified BSD License. See COPYING.

// Package timer provides a simple timer for tracking when the
// specific time duration has elapsed.
package timer

import (
	"fmt"
	"time"
)

type timer struct {
	duration time.Duration
	started  time.Time
}

// Expired returns true if the timer's duration has elapsed since it was started.
func (t *timer) Expired() bool {
	return time.Since(t.started) > t.duration
}

// Start sets the timer's start time to the current time.
func (t *timer) Start() {
	t.started = time.Now()
}

// NewTimer creates and returns a timer with the specified duration.
// Note that the timer is not started automatically.
func NewTimer(duration time.Duration) *timer {
	return &timer{
		duration: duration,
	}
}

func MsString(duration time.Duration) string {
	return fmt.Sprintf("%.2fms", float64(duration.Nanoseconds())/1e6)
}
