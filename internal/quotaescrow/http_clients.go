package quotaescrow

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
)

// HTTPClients deliberately ignores HTTP_PROXY/HTTPS_PROXY and the panel's
// general proxy. The separately returned fallback can only use the dedicated
// loopback accounting-sync bridge and is used by SyncTransport as its third path.
func HTTPClients(trust *tls.Config, accountingProxy string) (*http.Client, *http.Client, error) {
	if trust == nil || trust.RootCAs == nil || trust.InsecureSkipVerify {
		return nil, nil, errors.New("mesh requires explicit verified TLS trust")
	}
	base := func() *http.Transport {
		config := trust.Clone()
		config.MinVersion = tls.VersionTLS13
		return &http.Transport{TLSClientConfig: config, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, IdleConnTimeout: 30 * time.Second, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 2}
	}
	client := func(transport *http.Transport) *http.Client {
		return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	direct := client(base())
	if accountingProxy == "" {
		return direct, nil, nil
	}
	u, err := url.Parse(accountingProxy)
	if err != nil || u.Scheme != "socks5" || u.Hostname() != "127.0.0.1" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, nil, errors.New("invalid dedicated accounting bridge")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 62780 || port > 62789 {
		return nil, nil, errors.New("accounting bridge port is outside its reserved range")
	}
	dialer, err := proxy.SOCKS5("tcp", u.Host, nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		return nil, nil, err
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, nil, errors.New("accounting bridge cannot honor cancellation")
	}
	fallback := base()
	fallback.DialContext = contextDialer.DialContext
	return direct, client(fallback), nil
}
