package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type credentials struct{ Username, Password, TOTP string }
type config struct {
	Store        string `json:"store"`
	Machine      string `json:"machine,omitempty"`
	ResourcePath string `json:"resource_path,omitempty"`
	ICACommand   string `json:"ica_command,omitempty"`
}

func promptStore(input io.Reader, output io.Writer) (string, error) {
	fmt.Fprint(output, "Store URL (HTTPS): ")
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", errors.New("store selection requires input; pass --store instead")
	}
	store := strings.TrimSpace(line)
	if store == "" {
		return "", errors.New("store URL is required")
	}
	session, err := newSession(context.Background(), store, false)
	if err != nil {
		return "", err
	}
	return session.store.String(), nil
}

func readConfig(path string) (config, error) {
	var c config
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("invalid configuration: %w", err)
	}
	return c, nil
}

func privateWrite(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pomela-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func saveConfig(path string, c config) error {
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	return privateWrite(path, append(b, '\n'))
}

func choose(resources []resource, wanted string, wizard bool) (resource, error) {
	if len(resources) == 0 {
		return resource{}, errors.New("the store returned no available machines or apps")
	}
	if wanted != "" {
		for _, r := range resources {
			if r.ID == wanted {
				return r, nil
			}
		}
		var matches []resource
		for _, r := range resources {
			if strings.EqualFold(r.Name, wanted) {
				matches = append(matches, r)
			}
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
		return resource{}, errors.New("configured machine is missing or ambiguous; run pomela setup to select again")
	}
	if !wizard {
		return resource{}, errors.New("no machine configured; run pomela setup in a terminal or pass --machine")
	}
	for i, r := range resources {
		fmt.Printf("%d) %s [%s]\n", i+1, r.Name, r.ID)
	}
	fmt.Print("Select machine: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return resource{}, errors.New("machine selection requires terminal input or --machine")
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(resources) {
		return resource{}, errors.New("invalid machine selection")
	}
	return resources[n-1], nil
}
