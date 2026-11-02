package runtime

import (
	"context"
	"errors"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"testing"
)

func TestLocalMeshGatePreventsHotReaddition(t *testing.T) {
	local := NewLocal(LocalDeps{APIPort: func() int { t.Fatal("blocked user reached core API"); return 0 }, ClientAllowed: func(email string) (bool, error) {
		if email != "blocked" {
			t.Fatal(email)
		}
		return false, nil
	}})
	if err := local.AddUser(context.Background(), &model.Inbound{Protocol: model.VLESS}, map[string]any{"email": "blocked"}); err != nil {
		t.Fatal(err)
	}
}

func TestLocalMeshReadFailureDoesNotDeleteRunningInbound(t *testing.T) {
	expected := errors.New("accounting unavailable")
	local := NewLocal(LocalDeps{APIPort: func() int { t.Fatal("inbound removed before admission check"); return 0 }, FilterInbound: func(*model.Inbound) (*model.Inbound, error) { return nil, expected }})
	old := &model.Inbound{Protocol: model.VLESS, Enable: true}
	if err := local.UpdateInbound(context.Background(), old, old); !errors.Is(err, expected) {
		t.Fatal(err)
	}
}
