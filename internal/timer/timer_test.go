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
