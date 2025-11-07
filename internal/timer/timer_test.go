// Copyright (C) 2025 Jan Wrobel <jan@wwwhisper.io>
// This program is freely distributable under the terms of the
// Simplified BSD License. See COPYING.

package timer

import (
	"testing"
	"time"
)

func TestTimer(t *testing.T) {
	tmr := NewTimer(2 * time.Hour)
	if !tmr.Expired() {
		t.Errorf("Not started timer should be expired")
	}
	tmr.Start()
	if tmr.Expired() {
		t.Errorf("Timer incorrectly expired")
	}
	tmr = NewTimer(time.Nanosecond)
	tmr.Start()
	for tmr.Expired() == false {
		// The loop and the test will hang forever if the one nanosecond
		// timer does not expire.
	}
}

func TestMsString(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "zero duration",
			duration: 0,
			expected: "0.00ms",
		},
		{
			name:     "1 nanosecond",
			duration: 1 * time.Nanosecond,
			expected: "0.00ms",
		},
		{
			name:     "1 microsecond",
			duration: 1 * time.Microsecond,
			expected: "0.00ms",
		},
		{
			name:     "10 microseconds",
			duration: 10 * time.Microsecond,
			expected: "0.01ms",
		},
		{
			name:     "100 microseconds",
			duration: 100 * time.Microsecond,
			expected: "0.10ms",
		},
		{
			name:     "1 millisecond",
			duration: 1 * time.Millisecond,
			expected: "1.00ms",
		},
		{
			name:     "1.5 milliseconds",
			duration: 1500 * time.Microsecond,
			expected: "1.50ms",
		},
		{
			name:     "1.234 milliseconds",
			duration: 1234 * time.Microsecond,
			expected: "1.23ms",
		},
		{
			name:     "1.235 milliseconds",
			duration: 1235 * time.Microsecond,
			expected: "1.24ms",
		},
		{
			name:     "10 milliseconds",
			duration: 10 * time.Millisecond,
			expected: "10.00ms",
		},
		{
			name:     "100 milliseconds",
			duration: 100 * time.Millisecond,
			expected: "100.00ms",
		},
		{
			name:     "1 second",
			duration: 1 * time.Second,
			expected: "1000.00ms",
		},
		{
			name:     "1.5 seconds",
			duration: 1500 * time.Millisecond,
			expected: "1500.00ms",
		},
		{
			name:     "complex duration",
			duration: 2*time.Second + 345*time.Millisecond + 678*time.Microsecond,
			expected: "2345.68ms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MsString(tt.duration)
			if result != tt.expected {
				t.Errorf("MsString(%v) = %q, expected %q", tt.duration, result, tt.expected)
			}
		})
	}
}
