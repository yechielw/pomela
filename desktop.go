package main

import (
	"bytes"
	"errors"
	"html"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Nix supplies an absolute path, so desktop launchers need no shell PATH setup.
var dialogCommand = "zenity"
var errDialogCancelled = errors.New("dialog cancelled")

type desktopDialogs struct{}

func (desktopDialogs) run(args ...string) (string, error) {
	out, err := exec.Command(dialogCommand, args...).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 && len(bytes.TrimSpace(exit.Stderr)) == 0 {
			return "", errDialogCancelled
		}
		return "", errors.New("cannot open graphical dialog; use the Nix package within your desktop session")
	}
	return strings.TrimSuffix(string(out), "\n"), nil
}

func (ui desktopDialogs) entry(label string, hidden bool) (string, error) {
	args := []string{"--entry", "--title=Pomela", "--text=" + html.EscapeString(label)}
	if hidden {
		args = append(args, "--hide-text")
	}
	return ui.run(args...)
}

func (ui desktopDialogs) store() (string, error) {
	value, err := ui.entry("Enter your Citrix store URL (HTTPS)", false)
	if err != nil {
		return "", err
	}
	// Share the CLI wizard's validation and normalization.
	return promptStore(strings.NewReader(value+"\n"), io.Discard)
}

func (ui desktopDialogs) credentials() (credentials, error) {
	username, err := ui.entry("Entra sign-in username", false)
	if err != nil {
		return credentials{}, err
	}
	password, err := ui.entry("Password (stored in your OS keyring)", true)
	if err != nil {
		return credentials{}, err
	}
	seed, err := ui.entry("TOTP seed or otpauth URI (leave blank if not required)", true)
	if err != nil {
		return credentials{}, err
	}
	c := credentials{strings.TrimSpace(username), password, strings.TrimSpace(seed)}
	return c, validateCredentials(c)
}

func (ui desktopDialogs) choose(resources []resource) (resource, error) {
	if len(resources) == 0 {
		return resource{}, errors.New("the store returned no available machines or apps")
	}
	args := []string{"--list", "--title=Pomela — Choose desktop", "--text=Choose the desktop or app to save as your default", "--column=ID", "--column=Desktop", "--hide-column=1", "--print-column=1", "--width=640", "--height=420", "--ok-label=Select", "--"}
	for i, r := range resources {
		args = append(args, strconv.Itoa(i+1), r.Name)
	}
	value, err := ui.run(args...)
	if err != nil {
		return resource{}, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 1 || n > len(resources) {
		return resource{}, errors.New("no valid desktop selected")
	}
	return resources[n-1], nil
}

func (ui desktopDialogs) reportError(err error) {
	// Keep an owner-only diagnostic if a launcher discards stderr or the dialog
	// cannot open. Authentication errors already omit credentials and tokens.
	state := os.Getenv("XDG_STATE_HOME")
	if state == "" {
		if home, e := os.UserHomeDir(); e == nil {
			state = filepath.Join(home, ".local", "state")
		}
	}
	if state != "" {
		_ = privateWrite(filepath.Join(state, "pomela", "last-error.log"), []byte(err.Error()+"\n"))
	}
	_, _ = ui.run("--error", "--title=Pomela — Connection failed", "--text="+html.EscapeString(err.Error()), "--width=480")
}

func defaultConfigPath(root string, desktop bool) string {
	if !desktop {
		if _, err := os.Stat(filepath.Join(".pomela", "config.json")); err == nil {
			return filepath.Join(".pomela", "config.json")
		}
	}
	return filepath.Join(root, "pomela", "config.json")
}

func (ui desktopDialogs) getCredentials(k credentialStore, store string) (credentials, error) {
	c, err := getCredentials(k, store)
	if !errors.Is(err, errNoCredentials) {
		return c, err
	}
	c, err = ui.credentials()
	if err != nil {
		return credentials{}, err
	}
	if err = putCredentials(k, store, c); err != nil {
		return credentials{}, err
	}
	return c, nil
}
