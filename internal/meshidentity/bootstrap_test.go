package meshidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestGenerateIndependentPrivateIdentitiesWithoutOverwrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "bundle")
	members := []Member{{Name: "master", Owner: "guid-a", Endpoint: "https://127.0.0.1:45601/exchange", Listen: "0.0.0.0:45601", InstallDir: "/etc/x-ui/mesh"}, {Name: "node", Owner: "guid-b", Endpoint: "https://node.example:45602/exchange", Listen: "0.0.0.0:45602", InstallDir: "/etc/x-ui/mesh"}}
	now := time.Now().UTC()
	if err := Generate(root, members, now); err != nil {
		t.Fatal(err)
	}
	ca, _ := os.ReadFile(filepath.Join(root, "ca.pem"))
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("invalid CA")
	}
	seenKeys := map[string]bool{}
	for i, member := range members {
		dir := filepath.Join(root, member.Name)
		body, err := os.ReadFile(filepath.Join(dir, "identity.json"))
		if err != nil {
			t.Fatal(err)
		}
		var id identity
		if err := json.Unmarshal(body, &id); err != nil {
			t.Fatal(err)
		}
		if id.Owner != member.Owner || len(id.PeerKeys) != 2 || len(id.Peers) != 2 || len(id.PrivateKey) != 64 || !bytes.Equal(ed25519.PrivateKey(id.PrivateKey).Public().(ed25519.PublicKey), id.PeerKeys[id.Owner]) || bytes.Equal(id.Authority, id.PeerKeys[id.Owner]) || seenKeys[string(id.PrivateKey)] {
			t.Fatal("key separation/scope failed")
		}
		seenKeys[string(id.PrivateKey)] = true
		if _, err := os.Stat(filepath.Join(dir, "authority-private.json")); !os.IsNotExist(err) {
			t.Fatal("authority was distributed to a member")
		}
		certPEM, _ := os.ReadFile(filepath.Join(dir, "cert.pem"))
		block, _ := pem.Decode(certPEM)
		if block == nil {
			t.Fatal("missing leaf")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(cert.PublicKey.(ed25519.PublicKey), id.Authority) || bytes.Equal(cert.PublicKey.(ed25519.PublicKey), id.PeerKeys[id.Owner]) {
			t.Fatal("TLS and accounting keys were reused")
		}
		host := []string{"127.0.0.1", "node.example"}[i]
		for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
			if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: host, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
				t.Fatal(err)
			}
		}
		if runtime.GOOS != "windows" {
			info, _ := os.Stat(filepath.Join(dir, "identity.json"))
			if info.Mode().Perm() != 0600 {
				t.Fatal("private key permissions", info.Mode())
			}
		}
	}
	before, _ := os.ReadFile(filepath.Join(root, "authority-private.json"))
	if err := Generate(root, members, now); err == nil {
		t.Fatal("overwrote existing bundle")
	}
	after, _ := os.ReadFile(filepath.Join(root, "authority-private.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("authority key changed")
	}
	if _, err := os.Stat(filepath.Join(root, "COMPLETE.json")); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateRejectsTraversalAndDuplicateIdentityBeforeWriting(t *testing.T) {
	base := Member{Name: "good", Owner: "a", Endpoint: "https://127.0.0.1:45601/exchange", Listen: "0.0.0.0:45601", InstallDir: "/etc/x-ui/mesh"}
	for _, kind := range []string{"name", "directory", "duplicate", "plaintext"} {
		t.Run(kind, func(t *testing.T) {
			member := base
			members := []Member{member}
			switch kind {
			case "name":
				members[0].Name = "../escape"
			case "directory":
				members[0].InstallDir = "/etc/../etc/x-ui"
			case "duplicate":
				members = append(members, member)
			case "plaintext":
				members[0].Endpoint = "http://127.0.0.1:45601/exchange"
			}
			out := filepath.Join(t.TempDir(), "bundle")
			if Generate(out, members, time.Now()) == nil {
				t.Fatal("accepted invalid bootstrap")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("invalid request created secrets")
			}
		})
	}
}
