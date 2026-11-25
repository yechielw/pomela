package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fakeDialogs(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	command := filepath.Join(dir, "zenity")
	log := filepath.Join(dir, "arguments")
	if err := os.WriteFile(command, []byte("#!"+sh+"\nprintf '%s\\n' \"$@\" >> \"$POMELA_TEST_DIALOG_LOG\"\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POMELA_TEST_DIALOG_LOG", log)
	old := dialogCommand
	dialogCommand = command
	t.Cleanup(func() { dialogCommand = old })
	return log
}

func TestDesktopSelectionUsesStableResourceID(t *testing.T) {
	log := fakeDialogs(t, "printf '2\\n'")
	resources := []resource{{ID: "first", Name: "Same name"}, {ID: "second", Name: "Same name"}}
	r, err := (desktopDialogs{}).choose(resources)
	if err != nil || r.ID != "second" {
		t.Fatalf("selection: %v %v", r, err)
	}
	args, _ := os.ReadFile(log)
	if !strings.Contains(string(args), "--hide-column=1\n") {
		t.Fatal("missing hidden ID column")
	}
}

func TestDesktopCredentialWizardOnlyWhenMissing(t *testing.T) {
	log := fakeDialogs(t, `case "$*" in
  *username*) printf 'user@example.org\n';;
  *Password*) printf '  secret $ value  \n';;
  *TOTP*) printf 'JBSWY3DPEHPK3PXP\n';;
  *) exit 2;;
esac`)
	k := &memoryKeyring{}
	ui := desktopDialogs{}
	c, err := ui.getCredentials(k, "https://store.test")
	if err != nil || c.Password != "  secret $ value  " {
		t.Fatalf("credential wizard failed: %v", err)
	}
	stored, err := getCredentials(k, "https://store.test")
	if err != nil || stored != c {
		t.Fatal("credentials were not verified in keyring")
	}
	args, _ := os.ReadFile(log)
	if strings.Contains(string(args), c.Password) || strings.Contains(string(args), c.TOTP) {
		t.Fatal("secret passed in dialog arguments")
	}
	if strings.Count(string(args), "--hide-text\n") != 2 {
		t.Fatal("password and seed must both be hidden")
	}
	dialogCommand = filepath.Join(t.TempDir(), "must-not-run")
	if saved, err := ui.getCredentials(k, "https://store.test"); err != nil || saved != c {
		t.Fatal("saved credentials prompted again")
	}
	k.getError = errors.New("locked")
	if _, err := ui.getCredentials(k, "https://store.test"); err == nil {
		t.Fatal("keyring failure ignored")
	}
}

func TestDesktopDialogCancellation(t *testing.T) {
	fakeDialogs(t, "exit 1")
	if _, err := (desktopDialogs{}).store(); !errors.Is(err, errDialogCancelled) {
		t.Fatal("cancel not propagated")
	}
}

func TestDesktopDialogFailureIsNotCancellation(t *testing.T) {
	fakeDialogs(t, "echo 'cannot open display' >&2; exit 1")
	if _, err := (desktopDialogs{}).store(); err == nil || errors.Is(err, errDialogCancelled) {
		t.Fatal("dialog startup failure treated as cancellation")
	}
}

func TestDesktopConfigDoesNotDependOnWorkingDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := saveConfig(".pomela/config.json", config{Store: "https://local.test"}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if got := defaultConfigPath(root, true); got != filepath.Join(root, "pomela", "config.json") {
		t.Fatal("desktop used CWD configuration")
	}
	if got := defaultConfigPath(root, false); got != filepath.Join(".pomela", "config.json") {
		t.Fatal("CLI local configuration changed")
	}
}

func TestDesktopWizardPersistsStoreWithoutTerminal(t *testing.T) {
	fakeDialogs(t, `case "$*" in
  *"store URL"*) printf 'store.test\n';;
  *username*) exit 1;;
  *) exit 2;;
esac`)
	t.Chdir(t.TempDir())
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	t.Setenv("POMELA_STORE", "")
	oldArgs, oldStdin := os.Args, os.Stdin
	os.Args = []string{"pomela", "credentials", "set", "--desktop"}
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = input
	t.Cleanup(func() { os.Args = oldArgs; os.Stdin = oldStdin; input.Close() })
	if err := run(); err != nil {
		t.Fatal(err)
	}
	cfg, err := readConfig(filepath.Join(root, "pomela", "config.json"))
	if err != nil || cfg.Store != "https://store.test" {
		t.Fatal("graphical store selection was not saved")
	}
}

func TestDesktopErrorsAreVisibleAndPrivate(t *testing.T) {
	log := fakeDialogs(t, "exit 0")
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	(desktopDialogs{}).reportError(errors.New("failed <request>"))
	path := filepath.Join(state, "pomela", "last-error.log")
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "failed <request>\n" {
		t.Fatal("error diagnostic missing")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("error diagnostic not private")
	}
	args, _ := os.ReadFile(log)
	if !strings.Contains(string(args), "--error\n") || !strings.Contains(string(args), "failed &lt;request&gt;") {
		t.Fatal("error dialog missing or markup unescaped")
	}
}

func TestICAStartupFailureIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	if err = startICA(exec.Command(sh, "-c", "exit 7")); err == nil {
		t.Fatal("immediate client failure was ignored")
	}
	if err = startICA(exec.Command(sh, "-c", "exit 0")); err != nil {
		t.Fatal(err)
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sleep, "10")
	start := time.Now()
	if err = startICA(cmd); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	if time.Since(start) > 3*time.Second {
		t.Fatal("launcher waited for the ICA client session to end")
	}
}
