package service

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// MeshConfig is host-bound and never part of browser settings or API responses.
// Membership signing authority and per-node usage keys are distinct identities.
type MeshConfig struct {
	Owner      string            `json:"owner"`
	PrivateKey []byte            `json:"privateKey"`
	Authority  []byte            `json:"authority"`
	Listen     string            `json:"listen"`
	CertFile   string            `json:"certFile"`
	KeyFile    string            `json:"keyFile"`
	CAFile     string            `json:"caFile"`
	StateDir   string            `json:"stateDir"`
	Peers      map[string]string `json:"peers"`
	PeerKeys   map[string][]byte `json:"peerKeys,omitempty"`
}

func LoadMeshConfig(path string) (*MeshConfig, *tls.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 65536 || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, nil, errors.New("mesh identity file must be private, regular and bounded")
	}
	var c MeshConfig
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return nil, nil, errors.New("invalid mesh identity file")
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, nil, errors.New("trailing mesh identity data")
	}
	if err = c.validate(); err != nil {
		return nil, nil, err
	}
	ca, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, nil, errors.New("mesh trust bundle unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, nil, errors.New("invalid mesh trust bundle")
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, nil, errors.New("mesh TLS identity unavailable")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	intermediates := x509.NewCertPool()
	for _, raw := range cert.Certificate[1:] {
		parsed, e := x509.ParseCertificate(raw)
		if e != nil {
			return nil, nil, e
		}
		intermediates.AddCert(parsed)
	}
	self, _ := url.Parse(c.Peers[c.Owner])
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err = leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, DNSName: self.Hostname(), KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return nil, nil, errors.New("mesh certificate does not match local endpoint and trust")
		}
	}
	return &c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, Certificates: []tls.Certificate{cert}}, nil
}

func (c *MeshConfig) validate() error {
	if c.Owner == "" || len(c.Owner) > 128 || len(c.PrivateKey) != ed25519.PrivateKeySize || len(c.Authority) != ed25519.PublicKeySize {
		return errors.New("invalid mesh identity")
	}
	k := ed25519.PrivateKey(c.PrivateKey)
	if !bytes.Equal(k, ed25519.NewKeyFromSeed(k.Seed())) || bytes.Equal(k.Public().(ed25519.PublicKey), c.Authority) {
		return errors.New("invalid or reused mesh signing key")
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || port == "" || (host != "" && net.ParseIP(host) == nil) {
		return errors.New("invalid mesh listen address")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("invalid mesh listen port")
	}
	if len(c.Peers) == 0 || len(c.Peers) > 256 || c.Peers[c.Owner] == "" {
		return errors.New("invalid mesh peer registry")
	}
	for id, address := range c.Peers {
		u, e := url.Parse(address)
		if id == "" || len(id) > 128 || e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/exchange" {
			return errors.New("mesh peers require explicit HTTPS exchange endpoints")
		}
	}
	if len(c.PeerKeys) != 0 {
		if len(c.PeerKeys) != len(c.Peers) {
			return errors.New("incomplete pinned member keys")
		}
		seen := map[string]bool{}
		for owner, key := range c.PeerKeys {
			if c.Peers[owner] == "" || len(key) != ed25519.PublicKeySize || bytes.Equal(key, c.Authority) || seen[string(key)] {
				return errors.New("invalid pinned member keys")
			}
			seen[string(key)] = true
		}
		if !bytes.Equal(c.PeerKeys[c.Owner], k.Public().(ed25519.PublicKey)) {
			return errors.New("local usage key is not pinned")
		}
	}
	for _, p := range []string{c.CertFile, c.KeyFile, c.CAFile, c.StateDir} {
		if !filepath.IsAbs(p) {
			return errors.New("mesh identity paths must be absolute")
		}
	}
	return nil
}
