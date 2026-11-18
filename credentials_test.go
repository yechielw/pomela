package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joho/godotenv"
	"github.com/zalando/go-keyring"
)

type memoryKeyring struct {
	items              map[string]string
	setError, getError error
	afterSet           func()
	corrupt            bool
}

func (k *memoryKeyring) Set(service, account, secret string) error {
	if k.setError != nil {
		return k.setError
	}
	if k.items == nil {
		k.items = map[string]string{}
	}
	if k.corrupt {
		secret = "{}"
	}
	k.items[service+":"+account] = secret
	if k.afterSet != nil {
		k.afterSet()
	}
	return nil
}
func (k *memoryKeyring) Get(service, account string) (string, error) {
	if k.getError != nil {
		return "", k.getError
	}
	v, ok := k.items[service+":"+account]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}
func (k *memoryKeyring) Delete(service, account string) error {
	delete(k.items, service+":"+account)
	return nil
}

func TestKeyringCredentials(t *testing.T) {
	k := &memoryKeyring{}
	c := credentials{"user@example.org", "password with $ and ' and \"", "JBSWY3DPEHPK3PXP"}
	if e := putCredentials(k, "https://STORE.test/", c); e != nil {
		t.Fatal(e)
	}
	got, e := getCredentials(k, "https://store.test")
	if e != nil || got != c {
		t.Fatal("credentials did not round-trip")
	}
	if _, e = getCredentials(k, "https://other.test"); e == nil {
		t.Fatal("credentials leaked to another store")
	}
	t.Setenv("POMELA_USERNAME", c.Username)
	t.Setenv("POMELA_PASSWORD", c.Password)
	if _, e = getCredentials(&memoryKeyring{}, "https://store.test"); e == nil {
		t.Fatal("plaintext environment fallback accepted")
	}
	k.getError = errors.New("backend message with secret")
	if _, e = getCredentials(k, "https://store.test"); e == nil || strings.Contains(e.Error(), "backend message") {
		t.Fatal("backend error leaked")
	}
}
func TestMigrateCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	original := "store=https://store.test\nexport username=user@example.org\npassword='line1\nline2 $literal'\ntotp=JBSWY3DPEHPK3PXP\nPOMELA_USERNAME=user@example.org\nPOMELA_PASSWORD='line1\nline2 $literal'\nPOMELA_TOTP=JBSWY3DPEHPK3PXP\nUNRELATED='keep me'\n"
	if e := os.WriteFile(path, []byte(original), 0600); e != nil {
		t.Fatal(e)
	}
	k := &memoryKeyring{}
	if e := migrateCredentials(k, "https://store.test", path); e != nil {
		t.Fatal(e)
	}
	values, e := godotenv.Read(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range credentialEnvKeys {
		if _, ok := values[key]; ok {
			t.Fatal("credential remains in dotenv:", key)
		}
	}
	if values["store"] != "https://store.test" || values["UNRELATED"] != "keep me" {
		t.Fatal("noncredential configuration lost")
	}
	got, e := getCredentials(k, "https://store.test")
	if e != nil || got.Password != "line1\nline2 $literal" {
		t.Fatal("password changed during migration")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("dotenv permissions")
	}
}
func TestMigrationKeepsPlaintextOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		k    *memoryKeyring
	}{
		{"write failure", &memoryKeyring{setError: errors.New("keyring locked")}},
		{"read failure", &memoryKeyring{getError: errors.New("keyring locked")}},
		{"incorrect readback", &memoryKeyring{corrupt: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".env")
			original := "username=user@example.org\npassword=secret\n"
			os.WriteFile(path, []byte(original), 0600)
			if e := migrateCredentials(tc.k, "https://store.test", path); e == nil {
				t.Fatal("expected migration failure")
			}
			b, e := os.ReadFile(path)
			if e != nil || string(b) != original {
				t.Fatal("plaintext changed despite migration failure")
			}
		})
	}
}
func TestMigrationRejectsSymlinksAndConcurrentChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	link := filepath.Join(dir, "link")
	os.WriteFile(path, []byte("username=user@example.org\npassword=secret\n"), 0600)
	if e := os.Symlink(path, link); e != nil {
		t.Skip("symlinks unavailable")
	}
	k := &memoryKeyring{}
	if e := migrateCredentials(k, "https://store.test", link); e == nil {
		t.Fatal("symlink accepted")
	}
	replacement := "username=changed@example.org\npassword=new\n"
	k.afterSet = func() { os.WriteFile(path, []byte(replacement), 0600) }
	if e := migrateCredentials(k, "https://store.test", path); e == nil {
		t.Fatal("concurrent change ignored")
	}
	b, _ := os.ReadFile(path)
	if string(b) != replacement {
		t.Fatal("concurrent edit lost")
	}
}
