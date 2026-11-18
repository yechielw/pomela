package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

func run() error {
	command := "connect"
	args := os.Args[1:]
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		command = args[0]
		args = args[1:]
	}
	action := ""
	if command == "credentials" {
		if len(args) == 0 {
			return errors.New("usage: pomela credentials [set|import-env|status|delete] [flags]")
		}
		action = args[0]
		args = args[1:]
		if action != "set" && action != "import-env" && action != "status" && action != "delete" {
			return errors.New("usage: pomela credentials [set|import-env|status|delete] [flags]")
		}
	}
	if command != "connect" && command != "list" && command != "setup" && command != "credentials" {
		return errors.New("usage: pomela [connect|list|setup|credentials] [flags]")
	}
	root, e := os.UserConfigDir()
	if e != nil {
		return e
	}
	defaultConfig := filepath.Join(root, "pomela", "config.json")
	if _, err := os.Stat(filepath.Join(".pomela", "config.json")); err == nil {
		defaultConfig = filepath.Join(".pomela", "config.json")
	}
	fs := flag.NewFlagSet("pomela "+command, flag.ContinueOnError)
	envPath := fs.String("env", ".env", "source dotenv file for credentials import-env only")
	configPath := fs.String("config", defaultConfig, "configuration file")
	machine := fs.String("machine", "", "resource ID or exact display name")
	store := fs.String("store", "", "store HTTPS URL")
	resourcePath := fs.String("resource-path", "", "override resource listing endpoint")
	output := fs.String("output", "", "save ICA to this path")
	noOpen := fs.Bool("no-open", false, "download ICA without starting Workspace")
	noninteractive := fs.Bool("non-interactive", false, "never prompt for store or machine selection")
	verbose := fs.Bool("verbose", false, "show request methods, hosts and paths (no query, body or secrets)")
	timeout := fs.Duration("timeout", 3*time.Minute, "total login and launch timeout")
	if e = fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	cfg, e := readConfig(*configPath)
	if e != nil {
		return e
	}
	if command == "credentials" && action == "import-env" {
		_, values, _, err := migrationInput(*envPath)
		if err != nil {
			return err
		}
		if value := values["POMELA_STORE"]; value != "" {
			cfg.Store = value
		} else if value := values["store"]; value != "" {
			cfg.Store = value
		}
	}
	if value := os.Getenv("POMELA_STORE"); value != "" {
		cfg.Store = value
	}
	if *store != "" {
		cfg.Store = *store
	}
	if *resourcePath != "" {
		cfg.ResourcePath = *resourcePath
	}
	if strings.TrimSpace(cfg.Store) == "" {
		if *noninteractive {
			return errors.New("no store configured; run pomela setup or pass --store")
		}
		cfg.Store, e = promptStore(os.Stdin, os.Stdout)
		if e != nil {
			return e
		}
		if e = saveConfig(*configPath, cfg); e != nil {
			return e
		}
		fmt.Println("Store saved to", *configPath)
	}
	if command == "credentials" {
		return credentialCommand(action, cfg, *configPath, *envPath)
	}
	c, e := getCredentials(systemKeyring{}, cfg.Store)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	s, e := newSession(ctx, cfg.Store, *verbose)
	if e != nil {
		return e
	}
	fmt.Println("Signing in…")
	final, e := s.login(c)
	if e != nil {
		return e
	}
	resources, base, e := s.resources(final, cfg.ResourcePath)
	if e != nil {
		return e
	}
	if command == "list" {
		for _, r := range resources {
			fmt.Printf("%s\t%s\n", r.ID, r.Name)
		}
		return nil
	}
	wanted := cfg.Machine
	if command == "setup" {
		wanted = ""
	}
	if *machine != "" {
		wanted = *machine
	}
	selected, e := choose(resources, wanted, !*noninteractive)
	if e != nil {
		return e
	}
	if command == "setup" || cfg.Machine == "" {
		cfg.Machine = selected.ID
		if e = saveConfig(*configPath, cfg); e != nil {
			return e
		}
		fmt.Println("Machine selection saved to", *configPath)
	}
	if command == "setup" {
		return nil
	}
	b, e := s.launchICA(base, selected)
	if e != nil {
		return e
	}
	path, e := writeICA(*output, b)
	if e != nil {
		return e
	}
	fmt.Println("ICA saved to", path)
	if *noOpen {
		return nil
	}
	if e = openICA(path, cfg.ICACommand); e != nil {
		return e
	}
	fmt.Println("Started Citrix Workspace for", selected.Name)
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "pomela:", e)
		os.Exit(1)
	}
}
