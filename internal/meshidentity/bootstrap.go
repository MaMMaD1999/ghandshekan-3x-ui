// Package meshidentity prepares operator-only trust bundles. It does not enable
// mesh, enroll a subscriber, contact a host, or copy an authority key to nodes.
package meshidentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Member struct {
	Name       string `json:"name"`
	Owner      string `json:"owner"`
	Endpoint   string `json:"endpoint"`
	Listen     string `json:"listen"`
	InstallDir string `json:"installDir"`
}
type identity struct {
	Owner      string            `json:"owner"`
	PrivateKey []byte            `json:"privateKey"`
	Authority  []byte            `json:"authority"`
	Listen     string            `json:"listen"`
	CertFile   string            `json:"certFile"`
	KeyFile    string            `json:"keyFile"`
	CAFile     string            `json:"caFile"`
	StateDir   string            `json:"stateDir"`
	Peers      map[string]string `json:"peers"`
	PeerKeys   map[string][]byte `json:"peerKeys"`
}

func exclusiveFile(name string, data []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}
func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
func pemKey(key ed25519.PrivateKey) ([]byte, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

// Generate requires a NEW output directory and never overwrites existing keys.
// Only the per-member directory belongs on that host. The authority and CA
// private keys at the bundle root stay with the operator/coordinator.
func Generate(output string, members []Member, now time.Time) error {
	if output == "" || len(members) == 0 || len(members) > 256 {
		return errors.New("invalid bootstrap scope")
	}
	names, owners, endpoints := map[string]bool{}, map[string]bool{}, map[string]bool{}
	validName := regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	for _, member := range members {
		u, err := url.Parse(member.Endpoint)
		listenHost, listenPort, listenErr := net.SplitHostPort(member.Listen)
		port, portErr := strconv.Atoi(listenPort)
		if !validName.MatchString(member.Name) || names[member.Name] || member.Owner == "" || len(member.Owner) > 128 || owners[member.Owner] || endpoints[member.Endpoint] {
			return errors.New("duplicate or invalid member identity")
		}
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "/exchange" || u.RawQuery != "" || u.Fragment != "" || u.Port() == "" {
			return errors.New("explicit HTTPS peer endpoint required")
		}
		if listenErr != nil || portErr != nil || port < 1 || port > 65535 || (listenHost != "" && net.ParseIP(listenHost) == nil) || u.Port() != listenPort {
			return errors.New("invalid peer listen endpoint")
		}
		if !path.IsAbs(member.InstallDir) || path.Clean(member.InstallDir) != member.InstallDir || member.InstallDir == "/" || strings.ContainsAny(member.InstallDir, "\\\r\n\x00") {
			return errors.New("absolute clean Linux installation directory required")
		}
		names[member.Name], owners[member.Owner], endpoints[member.Endpoint] = true, true, true
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return err
	}
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	caSerial, err := serial()
	if err != nil {
		return err
	}
	ca := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "Ghand Panel private mesh CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		return err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyPEM, err := pemKey(caPrivate)
	if err != nil {
		return err
	}
	if err := exclusiveFile(filepath.Join(output, "ca-private.pem"), caKeyPEM); err != nil {
		return err
	}
	if err := exclusiveFile(filepath.Join(output, "ca.pem"), caPEM); err != nil {
		return err
	}
	authority, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	authorityJSON, err := json.Marshal(struct {
		PrivateKey []byte `json:"privateKey"`
	}{authorityPrivate})
	if err != nil {
		return err
	}
	if err := exclusiveFile(filepath.Join(output, "authority-private.json"), authorityJSON); err != nil {
		return err
	}
	peers, keys, privateKeys := map[string]string{}, map[string][]byte{}, map[string]ed25519.PrivateKey{}
	for _, member := range members {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		peers[member.Owner], keys[member.Owner], privateKeys[member.Owner] = member.Endpoint, pub, key
	}
	for _, member := range members {
		dir := filepath.Join(output, member.Name)
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		n, err := serial()
		if err != nil {
			return err
		}
		endpoint, _ := url.Parse(member.Endpoint)
		leaf := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: member.Owner}, NotBefore: ca.NotBefore, NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		if ip := net.ParseIP(endpoint.Hostname()); ip != nil {
			leaf.IPAddresses = []net.IP{ip}
		} else {
			leaf.DNSNames = []string{endpoint.Hostname()}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caPrivate)
		if err != nil {
			return err
		}
		keyPEM, err := pemKey(key)
		if err != nil {
			return err
		}
		c := identity{Owner: member.Owner, PrivateKey: privateKeys[member.Owner], Authority: authority, Listen: member.Listen, CertFile: path.Join(member.InstallDir, "cert.pem"), KeyFile: path.Join(member.InstallDir, "key.pem"), CAFile: path.Join(member.InstallDir, "ca.pem"), StateDir: path.Join(member.InstallDir, "state"), Peers: peers, PeerKeys: keys}
		body, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		for name, data := range map[string][]byte{"identity.json": body, "cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "key.pem": keyPEM, "ca.pem": caPEM} {
			if err := exclusiveFile(filepath.Join(dir, name), data); err != nil {
				return err
			}
		}
	}
	manifest, err := json.MarshalIndent(struct {
		Members   []Member          `json:"members"`
		Authority []byte            `json:"authority"`
		Keys      map[string][]byte `json:"keys"`
		CreatedAt time.Time         `json:"createdAt"`
	}{members, authority, keys, now}, "", "  ")
	if err != nil {
		return err
	}
	return exclusiveFile(filepath.Join(output, "COMPLETE.json"), manifest)
}
