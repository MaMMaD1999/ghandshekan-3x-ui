package service

import "math"

// A reset or disappearing interface establishes a new baseline, not a burst.
func counterRate(current, previous uint64, seconds float64) uint64 {
	if seconds <= 0 || math.IsNaN(seconds) || current < previous {
		return 0
	}
	rate := float64(current-previous) / seconds
	if math.IsNaN(rate) || math.IsInf(rate, 0) || rate >= float64(math.MaxInt64) {
		return 0
	}
	return uint64(rate)
}
