//go:build meshcore

package xray

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	appstats "github.com/xtls/xray-core/app/stats"
	command "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// Run with -tags meshcore and the custom core module. This exercises protobuf
// wire compatibility against its real generated server, not a panel mock.
func TestMeshGateClientAgainstCustomCore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := appstats.NewManager(ctx, &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	command.RegisterStatsServiceServer(server, command.NewStatsServer(m))
	go server.Serve(lis)
	t.Cleanup(func() { server.Stop(); lis.Close() })
	conn, err := grpc.NewClient("passthrough:///meshcore", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	api := &XrayAPI{grpcClient: conn}
	var closed atomic.Int64
	m.TrackUserSession(ctx, "phone", func() { closed.Add(1) })
	for i := 0; i < 2; i++ {
		if err := api.ReconcileUserGates(ctx, []string{"phone"}); err != nil {
			t.Fatal(err)
		}
	}
	if closed.Load() != 1 {
		t.Fatal("live stream not interrupted exactly once")
	}
	if err := api.ReconcileUserGates(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !m.TrackUserSession(ctx, "phone", func() {}) {
		t.Fatal("renewed user still fenced")
	}
}
