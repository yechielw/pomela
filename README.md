# Pomela

<img src="pomela.png" alt="Pomela citrus P logo" width="160" />

A Go CLI for the Citrix gateway at `ctirix-store-url`. Sign-in is entirely headless HTTP: NetScaler nFactor → Entra password → authenticator TOTP → SAML callback → StoreFront gateway SSO. No Playwright, Chromium, Selenium, or browser runtime is needed.

Requires Go 1.25+ to build. Citrix Workspace must be installed locally to open an ICA session.

With Nix, the flake provides a `buildGoModule` package for x86_64 Linux. `nix run` uses the package directly:

```sh
nix build                         # build, run Go tests, install result/bin/pomela
nix run . -- credentials set      # configure the OS keyring
nix run .                         # connect using your saved configuration
```

`flake.lock` pins nixpkgs and the Go dependencies have a fixed vendor hash. Package sources include only Go source, module files, the license, the desktop entry, and the logo; local credentials, configuration, ICA files, and compiled binaries are excluded. Run within your desktop session to access its keyring and Citrix Workspace; Workspace itself is installed separately.

On Linux, the package also installs a **Pomela** application-menu entry with the citrus P logo from `pomela.png`. Install it with `nix profile install .`, or add the flake's package to your NixOS/Home Manager packages, to make it available to desktop launchers. `nix build` and `nix run` alone do not register an application-menu entry in your user profile.

The launcher runs once without opening a terminal. If setup is incomplete, graphical dialogs ask for the store, missing keyring credentials, and desktop selection. Password and TOTP fields are hidden, and credentials are stored in the OS keyring. The chosen desktop is saved; later launches connect directly. Cancelling a dialog exits without launching a session. **Choose desktop** and **Set credentials** context-menu actions also use graphical dialogs where supported. The Nix package includes Zenity for these dialogs.

Desktop launches use `$XDG_CONFIG_HOME/pomela/config.json` (normally `~/.config/pomela/config.json`) regardless of the launcher's working directory. Failures appear in an error dialog and are recorded in an owner-only `$XDG_STATE_HOME/pomela/last-error.log` (normally `~/.local/state/pomela/last-error.log`). The installed desktop file uses an absolute executable path and `Terminal=false`. The desktop file is installed at `share/applications/pomela.desktop`, and the transparent PNG artwork at `share/pixmaps/pomela.png`.

```sh
make build
./pomela credentials set
```

Credentials (username, password, TOTP seed) are stored together as a secret in the OS keyring, under service `pomela`, with a separate entry for each normalized store URL. On Linux this uses the desktop Secret Service (such as GNOME Keyring); macOS uses Keychain and Windows uses Credential Manager. The desktop keyring must be available and unlocked; an OS unlock prompt may appear. No browser is needed.

`credentials set` prompts without echoing inputs. The username must be your Entra sign-in UPN. The TOTP field accepts a Base32 seed or an `otpauth://totp/...` URI; leave it blank only if the account does not require TOTP. Re-run this command to replace credentials. Passwords and seeds are never supplied as command-line arguments or stored in configuration files.

To migrate an existing `.env`, run this once from your desktop terminal:

```sh
./pomela credentials import-env
./pomela credentials status
```

Migration imports `username`, `password`, and `totp` (or their `POMELA_USERNAME`, `POMELA_PASSWORD`, and `POMELA_TOTP` equivalents) **from the file only**, writes and verifies the keyring entry, then removes all those credential fields from `.env`. Other variables are retained; dotenv formatting and comments are regenerated. The file's store URL is saved in the regular configuration. If keyring writing or read-back fails, `.env` is left unchanged. `--env path/to/file` selects another migration source. Normal sign-in reads credentials only from the keyring; there is no dotenv or environment credential fallback.

Use `./pomela credentials delete` to remove the entry for the configured store. `--store` or `POMELA_STORE` overrides the configured store, including when setting, migrating, checking, or deleting credentials.

```sh
./pomela list                 # sign in and list enabled ICA desktops/apps
./pomela setup                # wizard: select and save a default, without launching
./pomela                     # sign in, select if needed, download ICA, open Workspace
./pomela --machine 'My Workstation'
./pomela --non-interactive    # use the saved selection; fail if none exists
./pomela --no-open --output ./desktop.ica
```

When no store is configured, the wizard prompts for its HTTPS URL, validates it, and saves it before continuing. There is no default store. `--store` or `POMELA_STORE` supplies a store without prompting; `--non-interactive` reports an error if none is available.

The CLI's first connection without a saved machine presents a numbered selection and saves its resource ID. `setup` changes that selection. Desktops appear first. `--machine` accepts a resource ID or an exact, unambiguous display name. For CLI commands, an existing `.pomela/config.json` in the current directory takes precedence over the platform's user configuration directory. Desktop mode always uses the user configuration directory. Use `--config` to choose another location explicitly. Credentials are never written to the configuration.

Example configuration:

```json
{
  "store": "https://ctirix-store-url",
  "machine": "DefaultAggregationGroup.\\My Workstation",
  "ica_command": "/opt/Citrix/ICAClient/wfica"
}
```

`ica_command` is an executable path, not a shell command. Pomela passes the ICA file as its sole argument. It otherwise detects `wfica` on Linux and falls back to the OS file association (`xdg-open`, `open`, or the Windows handler). A graphical desktop is needed for Workspace itself; authentication and ICA download work without one.

`--store`, `--resource-path`, `--timeout 5m`, and `--verbose` are also available. `--desktop` selects graphical dialogs instead of terminal prompts; the desktop entry supplies this automatically. `--env` is used only by `credentials import-env`. Verbose output contains request methods, hosts and paths, with query strings and request/response bodies omitted. The configured store and `login.microsoftonline.com` are the only permitted HTTP destinations. TLS verification stays enabled. Password and MFA rejection stop the flow without automatic credential retries. Device compliance, CAPTCHA, passkeys, push-only MFA, and additional federated identity providers are reported as unsupported challenges.

Configuration and generated ICA files use mode `0600`; temporary ICA directories use `0700`. `.env` and ICA files are excluded from Git. Treat ICA files as credentials: they may contain short-lived launch tickets. Without `--output`, a unique private directory under the system temp directory holds the file; Workspace may remove it when configured by the server. Remove leftover directories when no longer needed. Sign-in cookies exist only in memory and are discarded on exit.

```sh
make test
```

Tests exercise a simulated full HTTP login/SAML/StoreFront/ICA flow, RFC 6238 TOTP vectors, destination restrictions, machine ambiguity, file permissions, keyring round-trips, and migration success/failure handling. The actual gateway/Entra/TOTP/StoreFront flow and ICA download for My Workstation were verified during initial development. Desktop rendering in Workspace was not verified.

Protocol references: [Citrix StoreFront Web API](https://developer-docs.citrix.com/us/en/storefront/storefront-web-api/getting-started.html), [Entrance's headless Entra flow](https://github.com/PianoNic/Entrance). Entra's web login endpoints are not a stable public API, so changes to Microsoft's sign-in pages may require updates.
