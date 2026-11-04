package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

// Every request made with an upload token is signed by the Ed25519 key the
// token was bound to at login, so a copied token is useless without the key.
// The key stays on this machine: in the system keychain (macOS Keychain,
// Windows Credential Manager, or the Secret Service on Linux), or, where
// there is none, in credentials.json, readable only by the user.

// keychainService names this CLI's keychain items; each is for one API.
const keychainService = "urfluency-cli"

// keyStore keeps login keys (Ed25519 seeds) by API address.
type keyStore interface {
	Set(api string, seed []byte) error
	Get(api string) ([]byte, error)
	Delete(api string) error
}

// systemKeychain stores keys in the OS keychain. go-keyring passes the value
// to macOS's security tool on its standard input, never as an argument.
type systemKeychain struct{}

func (systemKeychain) Set(api string, seed []byte) error {
	return keyring.Set(keychainService, api, base64.RawURLEncoding.EncodeToString(seed))
}

func (systemKeychain) Get(api string) ([]byte, error) {
	s, err := keyring.Get(keychainService, api)
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func (systemKeychain) Delete(api string) error {
	err := keyring.Delete(keychainService, api)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// keys is where login keys go; tests replace it. URFLUENCY_NO_KEYCHAIN=1
// keeps them in credentials.json instead, for machines whose keychain
// cannot be unlocked without a desktop session.
var keys keyStore = systemKeychain{}

func useKeychain() bool { return os.Getenv("URFLUENCY_NO_KEYCHAIN") != "1" }

// memoryKeys is a keyStore in memory, for tests.
type memoryKeys struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (k *memoryKeys) Set(api string, seed []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil {
		k.m = map[string][]byte{}
	}
	k.m[api] = append([]byte(nil), seed...)
	return nil
}

func (k *memoryKeys) Get(api string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	seed, ok := k.m[api]
	if !ok {
		return nil, keyring.ErrNotFound
	}
	return seed, nil
}

func (k *memoryKeys) Delete(api string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, api)
	return nil
}

// privateKey returns the key the credentials' token is bound to.
func (c credentials) privateKey() (ed25519.PrivateKey, error) {
	var seed []byte
	switch c.KeyStore {
	case "keychain":
		var err error
		if seed, err = keys.Get(c.API); err != nil {
			return nil, fmt.Errorf("the key for this login is not in your keychain (%v); run urfluency login", err)
		}
	case "file":
		var err error
		if seed, err = base64.RawURLEncoding.DecodeString(c.Key); err != nil {
			return nil, errors.New("the key for this login is unreadable; run urfluency login")
		}
	default:
		return nil, errors.New("this login is from an older urfluency, which the API no longer accepts; run urfluency login")
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("the key for this login is unreadable; run urfluency login")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// signingString is what a request's signature covers. The API builds the same
// string (SigningString in urfluency-app); both test it against one vector.
func signingString(method, path string, stamp int64, body []byte, token string) string {
	tokenSum := sha256.Sum256([]byte(token))
	bodySum := sha256.Sum256(body)
	return "urfluency-request-v1\n" + method + "\n" + path + "\n" + strconv.FormatInt(stamp, 10) + "\n" +
		hex.EncodeToString(bodySum[:]) + "\n" + hex.EncodeToString(tokenSum[:])
}

// lastStamp keeps stamps increasing within one run, as the API requires.
var (
	stampMu   sync.Mutex
	lastStamp int64
)

func nextStamp() int64 {
	stampMu.Lock()
	defer stampMu.Unlock()
	lastStamp = max(lastStamp+1, time.Now().UnixMilli())
	return lastStamp
}

// signRequest adds the token, a stamp, and a signature to req, whose body is
// body.
func signRequest(req *http.Request, body []byte, token string, key ed25519.PrivateKey) {
	stamp := nextStamp()
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Urfluency-Stamp", strconv.FormatInt(stamp, 10))
	req.Header.Set("X-Urfluency-Signature", base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(key, []byte(signingString(req.Method, req.URL.Path, stamp, body, token)))))
}
