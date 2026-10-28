package detonators

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func ed25519Signer(t *testing.T) ssh.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}

func rsaSigner(t *testing.T) ssh.Signer {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return signer
}

func writeKnownHosts(t *testing.T, lines ...string) string {
	path := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600))
	return path
}

func TestHostKeyVerificationAcceptsOnlyTheKnownKey(t *testing.T) {
	known := ed25519Signer(t)
	file := writeKnownHosts(t, knownhosts.Line([]string{"detonation.lab"}, known.PublicKey()))

	callback, algorithms, err := hostKeyVerification([]string{file}, "detonation.lab:22")
	require.NoError(t, err)
	assert.Equal(t, []string{ssh.KeyAlgoED25519}, algorithms)

	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
	assert.NoError(t, callback("detonation.lab:22", remote, known.PublicKey()))
	assert.Error(t, callback("detonation.lab:22", remote, ed25519Signer(t).PublicKey()), "an impostor key must be rejected")
}

func TestHostKeyVerificationRejectsUnknownHost(t *testing.T) {
	file := writeKnownHosts(t, knownhosts.Line([]string{"other.lab"}, ed25519Signer(t).PublicKey()))

	_, _, err := hostKeyVerification([]string{file}, "detonation.lab:22")
	assert.ErrorContains(t, err, "is not in known_hosts")
}

func TestHostKeyVerificationNeedsAKnownHostsFile(t *testing.T) {
	_, _, err := hostKeyVerification([]string{filepath.Join(t.TempDir(), "missing")}, "detonation.lab:22")
	assert.ErrorContains(t, err, "no known_hosts file found")
}

func TestHostKeyVerificationSkipsMissingFiles(t *testing.T) {
	file := writeKnownHosts(t, knownhosts.Line([]string{"detonation.lab"}, ed25519Signer(t).PublicKey()))

	_, _, err := hostKeyVerification([]string{filepath.Join(t.TempDir(), "known_hosts2"), file}, "detonation.lab:22")
	assert.NoError(t, err)
}

func TestHostKeyVerificationHashedAndNonStandardPort(t *testing.T) {
	key := ed25519Signer(t)
	hashed := knownhosts.HashHostname(knownhosts.Normalize("detonation.lab:2222"))
	file := writeKnownHosts(t, hashed+" "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))))

	callback, _, err := hostKeyVerification([]string{file}, "detonation.lab:2222")
	require.NoError(t, err)
	assert.NoError(t, callback("detonation.lab:2222", &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2222}, key.PublicKey()))

	_, _, err = hostKeyVerification([]string{file}, "detonation.lab:22")
	assert.Error(t, err, "an entry for port 2222 must not vouch for port 22")
}

func TestAlgorithmsForRSAKeyIncludeSHA2(t *testing.T) {
	file := writeKnownHosts(t, knownhosts.Line([]string{"detonation.lab"}, rsaSigner(t).PublicKey()))

	_, algorithms, err := hostKeyVerification([]string{file}, "detonation.lab:22")
	require.NoError(t, err)
	assert.Equal(t, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}, algorithms)
}

func TestKnownHostsFilesEnvOverride(t *testing.T) {
	t.Setenv("THREATEST_SSH_KNOWN_HOSTS", "/a/known_hosts /b/known_hosts")
	assert.Equal(t, []string{"/a/known_hosts", "/b/known_hosts"}, knownHostsFiles("detonation.lab"))
}

// serveHandshake runs an in-process SSH server on loopback that offers the
// given host keys and completes the handshake for any client key.
func serveHandshake(t *testing.T, hostKeys ...ssh.Signer) string {
	config := &ssh.ServerConfig{NoClientAuth: true}
	for _, key := range hostKeys {
		config.AddHostKey(key)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if sconn, chans, reqs, err := ssh.NewServerConn(conn, config); err == nil {
					go ssh.DiscardRequests(reqs)
					for ch := range chans {
						ch.Reject(ssh.Prohibited, "test server")
					}
					sconn.Close()
				}
			}()
		}
	}()
	return listener.Addr().String()
}

func dialWith(t *testing.T, knownHostsFile, address string) error {
	callback, algorithms, err := hostKeyVerification([]string{knownHostsFile}, address)
	if err != nil {
		return err
	}
	client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
		User:              "detonator",
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(ed25519Signer(t))},
		HostKeyCallback:   callback,
		HostKeyAlgorithms: algorithms,
	})
	if err == nil {
		client.Close()
	}
	return err
}

func TestHandshakeNegotiatesTheKnownKeyType(t *testing.T) {
	// The server offers RSA and ed25519; only ed25519 is in known_hosts. The
	// client must ask for ed25519 rather than fail on the RSA key.
	hostKey := ed25519Signer(t)
	address := serveHandshake(t, rsaSigner(t), hostKey)
	file := writeKnownHosts(t, knownhosts.Line([]string{address}, hostKey.PublicKey()))

	assert.NoError(t, dialWith(t, file, address))
}

func TestHandshakeRejectsAnImpostorHost(t *testing.T) {
	address := serveHandshake(t, ed25519Signer(t))
	file := writeKnownHosts(t, knownhosts.Line([]string{address}, ed25519Signer(t).PublicKey()))

	err := dialWith(t, file, address)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key mismatch")
}
