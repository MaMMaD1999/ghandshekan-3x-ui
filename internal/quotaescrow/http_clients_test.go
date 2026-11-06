package quotaescrow

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMeshHTTPClientsIgnoreGeneralProxyAndRequireDedicatedFallback(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	trust := &tls.Config{RootCAs: pool}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	direct, fallback, err := HTTPClients(trust, "")
	if err != nil || fallback != nil {
		t.Fatal(err, fallback)
	}
	defer direct.CloseIdleConnections()
	response, err := direct.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal(response.StatusCode)
	}
	for _, address := range []string{"http://127.0.0.1:62780", "socks5://remote.example:62780", "socks5://127.0.0.1:1080", "socks5://user:pass@127.0.0.1:62780", "socks5://127.0.0.1:62780/path"} {
		if _, _, err := HTTPClients(trust, address); err == nil {
			t.Fatal("accepted unrelated proxy", address)
		}
	}
	direct, fallback, err = HTTPClients(trust, "socks5://127.0.0.1:62780")
	if err != nil || fallback == nil {
		t.Fatal(err)
	}
	defer direct.CloseIdleConnections()
	defer fallback.CloseIdleConnections()
	if _, _, err := HTTPClients(&tls.Config{RootCAs: pool, InsecureSkipVerify: true}, ""); err == nil {
		t.Fatal("accepted disabled certificate verification")
	}
}
