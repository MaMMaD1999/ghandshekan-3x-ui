package service

import (
	"math"
	"testing"
)

func TestCounterRateHandlesResetAndInvalidIntervals(t *testing.T) {
	for _, c := range []struct {
		name              string
		current, previous uint64
		seconds           float64
		want              uint64
	}{
		{"normal", 1500, 500, 2, 500},
		{"reset", 100, 10000, 2, 0},
		{"same timestamp", 1000, 0, 0, 0},
		{"clock reversed", 1000, 0, -1, 0},
		{"nan", 1000, 0, math.NaN(), 0},
		{"overflow", math.MaxUint64, 0, 0.1, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := counterRate(c.current, c.previous, c.seconds); got != c.want {
				t.Fatalf("got %d, want %d", got, c.want)
			}
		})
	}
}
