package quotaescrow

import (
	"math"
	"testing"
)

func TestAllocateRightsConservesEveryByteWithoutBillingWeights(t *testing.T) {
	owners := []string{"a", "b", "c"}
	for _, remaining := range []int64{0, 1, 2, 10, 1000, math.MaxInt64} {
		grants := allocateRights(remaining, owners, map[string]int64{"a": 8, "b": 1, "c": 1})
		var total int64
		for _, owner := range owners {
			if grants[owner] < 0 {
				t.Fatal("negative rights")
			}
			total += grants[owner]
		}
		if total != remaining {
			t.Fatal("allocation changed remaining balance", remaining, total)
		}
		if remaining == 1000 && (grants["a"] != 800 || grants["b"] != 100 || grants["c"] != 100) {
			t.Fatal(grants)
		}
	}
}

func TestControlOnlyMasterReservesNoTrafficRights(t *testing.T) {
	for _, remaining := range []int64{1, 3, 1001} {
		grants := allocateRights(remaining, []string{"master", "node-a", "node-b"}, map[string]int64{"master": 0})
		if grants["master"] != 0 || grants["node-a"]+grants["node-b"] != remaining {
			t.Fatal(grants)
		}
	}
}
