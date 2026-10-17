package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"kandev-plugin-microsandbox/internal/hosts"
)

// KeyComment labels the plugin's public key in a host's authorized_keys.
const KeyComment = "kandev-plugin-microsandbox"

// GenerateKey creates the plugin's ed25519 key. It returns the private key
// as an OpenSSH PEM block, for the plugin secret store, and the public half
// as an authorized_keys line.
func GenerateKey() (privatePEM string, authorized string, err error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ssh key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(private, KeyComment)
	if err != nil {
		return "", "", fmt.Errorf("encode ssh key: %w", err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		return "", "", fmt.Errorf("encode ssh public key: %w", err)
	}
	return string(pem.EncodeToMemory(block)), AuthorizedLine(sshPublic), nil
}

// ParseSigner reads a private key written by GenerateKey.
func ParseSigner(privatePEM string) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privatePEM))
	if err != nil {
		return nil, errors.New("stored ssh key is unreadable")
	}
	return signer, nil
}

// AuthorizedLine renders a public key as `<type> <base64> <comment>`.
func AuthorizedLine(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " " + KeyComment
}

// ParseHostKey reads a pinned host key line (`<type> <base64> [comment]`).
func ParseHostKey(line string) (ssh.PublicKey, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, errors.New("host key is not a valid public key line")
	}
	return key, nil
}

// Fingerprint is the SHA256 fingerprint OpenSSH shows for a key line, for
// the operator to compare against `ssh-keygen -lf` on the host.
func Fingerprint(line string) (string, error) {
	key, err := ParseHostKey(line)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(key), nil
}

// hostKeyAlgorithms lists the signature algorithms that verify a pinned key
// of this type. Offering only these makes the server present the pinned key
// rather than another of its host keys, which FixedHostKey would reject.
func hostKeyAlgorithms(key ssh.PublicKey) []string {
	if key.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{key.Type()}
}

// scanAlgorithms is the preference order for trust on first use.
var scanAlgorithms = []string{
	ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

var errScanned = errors.New("host key captured")

// ScanHostKey connects to dest and returns the host key it presents, for the
// operator to confirm before it is pinned. It stops at key exchange and
// never authenticates.
func ScanHostKey(ctx context.Context, dest string, dialer Dialer) (string, error) {
	user, host, port, err := hosts.ParseSSH(dest)
	if err != nil {
		return "", err
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w", address, err)
	}
	defer conn.Close()
	// Closing the connection is what unblocks a handshake on cancellation;
	// the ssh package would otherwise wait for its own timeout.
	defer context.AfterFunc(ctx, func() { _ = conn.Close() })()
	var captured ssh.PublicKey
	config := &ssh.ClientConfig{
		User:              user,
		HostKeyAlgorithms: scanAlgorithms,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return errScanned
		},
		Timeout: dialTimeout,
	}
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	_, _, _, err = ssh.NewClientConn(conn, address, config)
	if captured == nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", fmt.Errorf("ssh handshake with %s: %w", address, err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(captured))), nil
}
