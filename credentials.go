package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

const keyringService = "pomela"

type credentialStore interface {
	Set(service, account, secret string) error
	Get(service, account string) (string, error)
	Delete(service, account string) error
}
type systemKeyring struct{}

func (systemKeyring) Set(s, a, v string) error        { return keyring.Set(s, a, v) }
func (systemKeyring) Get(s, a string) (string, error) { return keyring.Get(s, a) }
func (systemKeyring) Delete(s, a string) error        { return keyring.Delete(s, a) }

func keyringAccessError(operation string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return errors.New("OS keyring access denied by process permissions; run this command in your desktop terminal")
	}
	return fmt.Errorf("cannot %s OS keyring; ensure the desktop keyring is available and unlocked", operation)
}

func credentialAccount(store string) (string, error) {
	s, e := newSession(context.Background(), store, false)
	if e != nil {
		return "", e
	}
	u := *s.store
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return "credentials:" + u.String(), nil
}
func validateCredentials(c credentials) error {
	if strings.TrimSpace(c.Username) == "" || c.Password == "" {
		return errors.New("username and password are required")
	}
	if c.TOTP != "" {
		if _, e := totp(c.TOTP, time.Now()); e != nil {
			return e
		}
	}
	return nil
}
func getCredentials(k credentialStore, store string) (credentials, error) {
	account, e := credentialAccount(store)
	if e != nil {
		return credentials{}, e
	}
	secret, e := k.Get(keyringService, account)
	if errors.Is(e, keyring.ErrNotFound) {
		return credentials{}, errors.New("no credentials in OS keyring for this store; run pomela credentials set or pomela credentials import-env")
	}
	if e != nil {
		return credentials{}, keyringAccessError("read", e)
	}
	var c credentials
	if json.Unmarshal([]byte(secret), &c) != nil {
		return c, errors.New("invalid keyring entry; run pomela credentials set")
	}
	if validateCredentials(c) != nil {
		return credentials{}, errors.New("incomplete or invalid keyring entry; run pomela credentials set")
	}
	return c, nil
}
func putCredentials(k credentialStore, store string, c credentials) error {
	if e := validateCredentials(c); e != nil {
		return e
	}
	account, e := credentialAccount(store)
	if e != nil {
		return e
	}
	b, e := json.Marshal(c)
	if e != nil {
		return errors.New("cannot encode credentials")
	}
	if e = k.Set(keyringService, account, string(b)); e != nil {
		return keyringAccessError("save to", e)
	}
	saved, e := getCredentials(k, store)
	if e != nil || saved != c {
		return errors.New("keyring read-back verification failed; plaintext credentials were not removed")
	}
	return nil
}

var credentialEnvKeys = []string{"username", "password", "totp", "POMELA_USERNAME", "POMELA_PASSWORD", "POMELA_TOTP"}

func migrationInput(path string) ([]byte, map[string]string, credentials, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, nil, credentials{}, errors.New("cannot read dotenv file for migration")
	}
	if !info.Mode().IsRegular() {
		return nil, nil, credentials{}, errors.New("migration requires a regular dotenv file, not a symbolic link")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, nil, credentials{}, errors.New("cannot read dotenv file for migration")
	}
	values, e := godotenv.Unmarshal(string(b))
	if e != nil {
		return nil, nil, credentials{}, errors.New("cannot parse dotenv file for migration")
	}
	get := func(primary, legacy string) string {
		if v, ok := values[primary]; ok {
			return v
		}
		return values[legacy]
	}
	c := credentials{get("POMELA_USERNAME", "username"), get("POMELA_PASSWORD", "password"), get("POMELA_TOTP", "totp")}
	if e = validateCredentials(c); e != nil {
		return nil, nil, credentials{}, errors.New("dotenv must contain a username, password, and valid TOTP seed if supplied")
	}
	return b, values, c, nil
}
func migrateCredentials(k credentialStore, store, path string) error {
	original, values, c, e := migrationInput(path)
	if e != nil {
		return e
	}
	if e = putCredentials(k, store, c); e != nil {
		return e
	}
	// Never remove edits made while a keyring-unlock prompt was open.
	current, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(current, original) {
		return errors.New("credentials saved to keyring, but dotenv changed during migration; file left untouched")
	}
	for _, key := range credentialEnvKeys {
		delete(values, key)
	}
	clean, e := godotenv.Marshal(values)
	if e != nil {
		return errors.New("credentials saved to keyring, but cannot rewrite dotenv")
	}
	if e = privateWrite(path, []byte("# Credentials moved to the OS keyring.\n"+clean+"\n")); e != nil {
		return errors.New("credentials saved to keyring, but cannot remove them from dotenv")
	}
	return nil
}

func promptCredential(label string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("credentials set requires a terminal; use credentials import-env for migration")
	}
	fmt.Fprint(os.Stderr, label+" (hidden): ")
	b, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if e != nil {
		return "", errors.New("cannot read credential from terminal")
	}
	return string(b), nil
}
func credentialCommand(action string, cfg config, configPath, envPath string) error {
	k := systemKeyring{}
	switch action {
	case "set":
		username, e := promptCredential("Entra username")
		if e != nil {
			return e
		}
		password, e := promptCredential("Password")
		if e != nil {
			return e
		}
		seed, e := promptCredential("TOTP seed or otpauth URI (blank if not required)")
		if e != nil {
			return e
		}
		if e = putCredentials(k, cfg.Store, credentials{strings.TrimSpace(username), password, strings.TrimSpace(seed)}); e != nil {
			return e
		}
		fmt.Println("Credentials saved and verified in OS keyring.")
	case "import-env":
		if e := saveConfig(configPath, cfg); e != nil {
			return e
		}
		if e := migrateCredentials(k, cfg.Store, envPath); e != nil {
			return e
		}
		fmt.Println("Credentials saved and verified in OS keyring; credential fields removed from", envPath)
	case "status":
		if _, e := getCredentials(k, cfg.Store); e != nil {
			return e
		}
		fmt.Println("Credentials are available in OS keyring for", cfg.Store)
	case "delete":
		account, e := credentialAccount(cfg.Store)
		if e != nil {
			return e
		}
		if e = k.Delete(keyringService, account); e != nil && !errors.Is(e, keyring.ErrNotFound) {
			return errors.New("cannot delete credentials from OS keyring")
		}
		fmt.Println("Credentials removed from OS keyring for", cfg.Store)
	default:
		return errors.New("usage: pomela credentials [set|import-env|status|delete] [flags]")
	}
	return nil
}
