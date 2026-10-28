package detonators

import (
	"errors"
	"fmt"
	"github.com/hashicorp/go-uuid"
	"github.com/kevinburke/ssh_config"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type SSHCommandExecutor struct {
	SSHHostname   string
	SSHUsername   string
	SSHKeyFile    string
	SSHConnection *ssh.Client
	isInitialized bool
}

func NewSSHCommandExecutor(hostname string, username string, keyFile string) (*SSHCommandExecutor, error) {
	return &SSHCommandExecutor{
		SSHHostname: hostname,
		SSHUsername: username,
		SSHKeyFile:  keyFile,
	}, nil
}

func (m *SSHCommandExecutor) init() error {
	var realHostname = m.SSHHostname
	if hostname := ssh_config.Get(m.SSHHostname, "HostName"); hostname != "" && hostname != m.SSHHostname {
		realHostname = hostname
	}

	var sshUser = m.SSHUsername
	if sshUser == "" {
		sshUser = ssh_config.Get(m.SSHHostname, "User")
	}

	var sshKey = m.SSHKeyFile
	if sshKey == "" {
		sshKey = ssh_config.Get(m.SSHHostname, "IdentityFile")
	}

	var sshPort = 22
	if port := ssh_config.Get(m.SSHHostname, "Port"); port != "" {
		parsedSshPort, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("unable to parse port %s: %v", port, err)
		}
		sshPort = parsedSshPort
	}

	sshKey, err := resolveSSHKeyPath(sshKey)
	if err != nil {
		return fmt.Errorf("unable to resolve path of private key at %s: %v", sshKey, err)
	}

	pemBytes, err := os.ReadFile(sshKey)
	if err != nil {
		return fmt.Errorf("unable to read private key file at %s: %v", sshKey, err)
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return fmt.Errorf("unable to parse private key file at %s: %v", sshKey, err)
	}

	sshAddress := net.JoinHostPort(realHostname, strconv.Itoa(sshPort))
	hostKeyCallback, hostKeyAlgorithms, err := hostKeyVerification(knownHostsFiles(m.SSHHostname), sshAddress)
	if err != nil {
		return err
	}

	var config = &ssh.ClientConfig{
		Config:            ssh.Config{},
		User:              sshUser,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		Timeout:           10 * time.Second,
	}

	log.Info("Connecting over SSH")
	conn, err := ssh.Dial("tcp", sshAddress, config)
	if err != nil {
		return fmt.Errorf("unable to establish SSH connection to %s: %v", sshAddress, err)
	}

	log.Info("Connection succeeded")

	m.SSHConnection = conn
	return nil
}

func (m *SSHCommandExecutor) RunCommand(command string) (string, error) {
	if !m.isInitialized {
		if err := m.init(); err != nil {
			return "", err
		}
		m.isInitialized = true
	}
	session, err := m.SSHConnection.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return "", err
	}

	id, _ := uuid.GenerateUUID()
	finalCommand := FormatCommand(command, id)
	log.Info("Running remote command: " + finalCommand)
	if err := session.Run(finalCommand); err != nil {
		return "", err
	}

	return id, nil
}

func resolveSSHKeyPath(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		usr, err := user.Current()
		if err != nil {
			return "", err
		}
		path = filepath.Join(usr.HomeDir, strings.TrimPrefix(path, "~/"))
	}
	return filepath.Abs(path)
}

// knownHostsFiles returns the known_hosts files to verify host keys against:
// THREATEST_SSH_KNOWN_HOSTS when set, else UserKnownHostsFile from the SSH
// config for this host (by default ~/.ssh/known_hosts ~/.ssh/known_hosts2).
func knownHostsFiles(sshHostname string) []string {
	files := os.Getenv("THREATEST_SSH_KNOWN_HOSTS")
	if files == "" {
		files = ssh_config.Get(sshHostname, "UserKnownHostsFile")
	}
	return strings.Fields(files)
}

// hostKeyVerification builds a host key callback from the known_hosts files
// that exist, and the host key algorithms known for address, so the server is
// only asked for key types that can be verified. It fails when address has no
// entry, rather than trusting the first key it sees.
func hostKeyVerification(files []string, address string) (ssh.HostKeyCallback, []string, error) {
	var existing []string
	for _, file := range files {
		path, err := resolveSSHKeyPath(file)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to resolve known_hosts path %s: %v", file, err)
		}
		if _, err := os.Stat(path); err == nil {
			existing = append(existing, path)
		}
	}
	if len(existing) == 0 {
		return nil, nil, fmt.Errorf("no known_hosts file found among %v: add the detonation host's key, after checking its fingerprint, before running remote detonations", files)
	}

	callback, err := knownhosts.New(existing...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read known_hosts: %v", err)
	}

	// Probing with a key that matches nothing makes knownhosts list the keys
	// it holds for this host.
	var keyErr *knownhosts.KeyError
	probeErr := callback(address, &net.TCPAddr{IP: net.IPv4zero}, probeKey{})
	if !errors.As(probeErr, &keyErr) || len(keyErr.Want) == 0 {
		return nil, nil, fmt.Errorf("host %s is not in known_hosts (%s): add its key, after checking its fingerprint, before running remote detonations", address, strings.Join(existing, ", "))
	}

	var algorithms []string
	for _, known := range keyErr.Want {
		for _, algorithm := range algorithmsForKeyType(known.Key.Type()) {
			if !slices.Contains(algorithms, algorithm) {
				algorithms = append(algorithms, algorithm)
			}
		}
	}
	return callback, algorithms, nil
}

// algorithmsForKeyType maps a known_hosts key type to the host key signature
// algorithms that verify against it. An ssh-rsa key also verifies the SHA-2
// signatures current servers prefer.
func algorithmsForKeyType(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

// probeKey is a public key that matches no known_hosts entry.
type probeKey struct{}

func (probeKey) Type() string                            { return "threatest-probe" }
func (probeKey) Marshal() []byte                         { return []byte("threatest-probe") }
func (probeKey) Verify(_ []byte, _ *ssh.Signature) error { return errors.New("probe key") }
