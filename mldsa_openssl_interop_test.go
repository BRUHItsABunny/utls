// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build opensslinterop

package tls

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const opensslInteropImage = "alpine:edge"

func TestOpenSSLMLDSAInterop(t *testing.T) {
	requireDocker(t)

	workDir := t.TempDir()
	generateOpenSSLMLDSACerts(t, workDir)

	t.Run("OpenSSL client verifies uTLS ML-DSA server", func(t *testing.T) {
		certPEM, err := os.ReadFile(filepath.Join(workDir, "server.crt"))
		if err != nil {
			t.Fatal(err)
		}
		keyPEM, err := os.ReadFile(filepath.Join(workDir, "server.key"))
		if err != nil {
			t.Fatal(err)
		}
		cert, err := X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		serverErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			defer conn.Close()
			serverErr <- Server(conn, &Config{
				Certificates: []Certificate{cert},
				MinVersion:   VersionTLS13,
				MaxVersion:   VersionTLS13,
			}).Handshake()
		}()

		hostPort := ln.Addr().(*net.TCPAddr).Port
		runDocker(t, workDir, "sh", "-lc", fmt.Sprintf(
			"apk add --no-cache openssl >/dev/null && printf 'Q\\n' | openssl s_client -connect host.docker.internal:%d -servername localhost -verify_hostname localhost -tls1_3 -groups X25519 -sigalgs mldsa44 -CAfile /w/ca.crt -verify_return_error -brief",
			hostPort,
		))
		if err := <-serverErr; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("uTLS client verifies OpenSSL ML-DSA server", func(t *testing.T) {
		containerID := runDockerOutput(t, workDir, "docker", "run", "-d", "--rm",
			"-v", dockerVolume(workDir)+":/w",
			"-p", "127.0.0.1::4433",
			opensslInteropImage,
			"sh", "-lc",
			"apk add --no-cache openssl >/dev/null && openssl s_server -accept 4433 -cert /w/server.crt -key /w/server.key -tls1_3 -groups X25519 -sigalgs mldsa44 -www -quiet",
		)
		containerID = strings.TrimSpace(containerID)
		t.Cleanup(func() {
			_ = exec.Command("docker", "rm", "-f", containerID).Run()
		})

		hostAddr := dockerPublishedAddress(t, containerID)
		time.Sleep(2 * time.Second)

		caPEM, err := os.ReadFile(filepath.Join(workDir, "ca.crt"))
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			t.Fatal("failed to parse OpenSSL test CA")
		}

		conn, err := net.Dial("tcp", hostAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		client := UClient(conn, &Config{
			ServerName: "localhost",
			RootCAs:    roots,
			MinVersion: VersionTLS13,
			MaxVersion: VersionTLS13,
		}, HelloChrome_150)
		if err := client.Handshake(); err != nil {
			t.Fatal(err)
		}
		if got := client.ConnectionState().Version; got != VersionTLS13 {
			t.Fatalf("version = %#x, want TLS 1.3", got)
		}
		if len(client.ConnectionState().PeerCertificates) == 0 {
			t.Fatal("OpenSSL server did not send a certificate")
		}
		expectMLDSAPublicKey(t, client.ConnectionState().PeerCertificates[0].PublicKey, MLDSA44)
	})
}

func requireDocker(t *testing.T) {
	t.Helper()

	cmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("Docker is required for OpenSSL interop tests: %v\n%s", err, out)
	}
}

func generateOpenSSLMLDSACerts(t *testing.T, workDir string) {
	t.Helper()

	runDocker(t, workDir, "sh", "-lc", strings.Join([]string{
		"apk add --no-cache openssl >/dev/null",
		"cd /w",
		"openssl version",
		"openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key",
		"openssl req -x509 -new -key ca.key -sha256 -days 30 -subj '/CN=utls interop test root' -out ca.crt",
		"openssl genpkey -algorithm ML-DSA-44 -out server.key",
		"openssl req -new -key server.key -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' -out server.csr",
		"openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -copy_extensions copy -out server.crt",
		"openssl x509 -in server.crt -noout -text | grep -E 'Public Key Algorithm|Signature Algorithm'",
	}, " && "))
}

func runDocker(t *testing.T, workDir string, args ...string) {
	t.Helper()

	baseArgs := []string{"run", "--rm", "--add-host=host.docker.internal:host-gateway", "-v", dockerVolume(workDir) + ":/w", opensslInteropImage}
	out := runDockerOutput(t, workDir, "docker", append(baseArgs, args...)...)
	t.Log(out)
}

func runDockerOutput(t *testing.T, workDir, name string, args ...string) string {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.Dir = workDir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

func dockerVolume(path string) string {
	return filepath.ToSlash(path)
}

func dockerPublishedAddress(t *testing.T, containerID string) string {
	t.Helper()

	out := runDockerOutput(t, "", "docker", "port", containerID, "4433/tcp")
	line := strings.TrimSpace(out)
	if line == "" {
		t.Fatalf("docker port returned no address for %s", containerID)
	}
	if strings.HasPrefix(line, "0.0.0.0:") {
		line = "127.0.0.1:" + strings.TrimPrefix(line, "0.0.0.0:")
	}
	if strings.HasPrefix(line, "[::]:") {
		line = "127.0.0.1:" + strings.TrimPrefix(line, "[::]:")
	}
	return line
}

func waitForTCP(t *testing.T, addr string) {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %v", addr, lastErr)
}
