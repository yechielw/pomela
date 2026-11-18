package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

type resource struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	LaunchURL       string   `json:"launchurl"`
	LaunchStatusURL string   `json:"launchstatusurl"`
	ClientTypes     []string `json:"clienttypes"`
	Disabled        bool     `json:"disabled"`
	Desktop         bool     `json:"isdesktop"`
}

func (s *session) storeRequest(base *url.URL, path string, v url.Values, method string) (*response, error) {
	u, e := s.resolve(base, path)
	if e != nil {
		return nil, e
	}
	if u.Host != s.store.Host {
		return nil, errors.New("store endpoint must be on the store host")
	}
	h := http.Header{"X-Citrix-IsUsingHTTPS": {"Yes"}, "X-Requested-With": {"XMLHttpRequest"}, "Referer": {base.String()}, "Accept": {"application/json, text/plain, */*"}}
	for _, c := range s.client.Jar.Cookies(u) {
		if strings.EqualFold(c.Name, "CsrfToken") {
			h.Set("Csrf-Token", c.Value)
			if method == "GET" {
				q := u.Query()
				q.Set("CsrfToken", c.Value)
				q.Set("IsUsingHttps", "Yes")
				u.RawQuery = q.Encode()
			}
		}
	}
	body := []byte(nil)
	ct := ""
	if method == "POST" {
		body = []byte(v.Encode())
		ct = "application/x-www-form-urlencoded"
	}
	return s.request(method, u, body, ct, h)
}
func (s *session) resources(final *response, override string) ([]resource, *url.URL, error) {
	base := *final.URL
	base.RawQuery = ""
	base.Fragment = ""
	if !strings.HasSuffix(base.Path, "/") {
		base.Path = base.Path[:strings.LastIndex(base.Path, "/")+1]
	}
	// Bootstrap StoreFront's web session and discover its resource endpoint.
	configuration, e := s.storeRequest(&base, "Home/Configuration", nil, "POST")
	if e != nil {
		return nil, nil, fmt.Errorf("StoreFront configuration: %w", e)
	}
	listPath := "Resources/List"
	if e == nil {
		var cfg struct {
			Proxy struct {
				Resources struct {
					List string `xml:"listURL,attr"`
				} `xml:"resourcesProxy"`
			} `xml:"storeProxy"`
		}
		if xml.Unmarshal(configuration.Body, &cfg) == nil && cfg.Proxy.Resources.List != "" {
			listPath = cfg.Proxy.Resources.List
		}
	}
	paths := []string{}
	if override != "" {
		paths = append(paths, override)
	} else {
		paths = append(paths, base.ResolveReference(&url.URL{Path: listPath}).String())
	}
	for _, path := range paths {
		for _, method := range []string{"POST"} {
			r, e := s.storeRequest(&base, path, url.Values{"format": {"json"}, "resourceDetails": {"Default"}}, method)
			if e != nil {
				continue
			}
			var listing struct {
				Resources    []resource `json:"resources"`
				Unauthorized bool       `json:"unauthorized"`
			}
			if json.Unmarshal(r.Body, &listing) != nil {
				continue
			}
			if listing.Unauthorized {
				if e := s.storefrontSSO(&base, r); e != nil {
					return nil, nil, e
				}
				r, e = s.storeRequest(&base, path, url.Values{"format": {"json"}, "resourceDetails": {"Default"}}, "POST")
				if e != nil {
					return nil, nil, e
				}
				listing.Unauthorized = false
				if json.Unmarshal(r.Body, &listing) != nil || listing.Unauthorized {
					return nil, nil, errors.New("StoreFront did not accept the gateway SSO session")
				}
			}
			if listing.Resources != nil {
				for _, r := range listing.Resources {
					if r.ID == "" || r.LaunchURL == "" {
						return nil, nil, errors.New("store resource missing ID or launch URL")
					}
				}
				var available []resource
				for _, r := range listing.Resources {
					if r.Disabled {
						continue
					}
					for _, typ := range r.ClientTypes {
						if typ == "ica30" {
							available = append(available, r)
							break
						}
					}
				}
				sort.SliceStable(available, func(i, j int) bool { return available[i].Desktop && !available[j].Desktop })
				return available, r.URL, nil
			}
		}
	}
	return nil, nil, errors.New("could not enumerate StoreFront resources; session may not be authenticated or resource_path needs configuration")
}

var challengeLocation = regexp.MustCompile(`location="([^"]+)"`)

func (s *session) storefrontSSO(base *url.URL, challenge *response) error {
	m := challengeLocation.FindStringSubmatch(challenge.Header.Get("CitrixWebReceiver-Authenticate"))
	if len(m) != 2 {
		return errors.New("StoreFront did not provide an authentication challenge URL")
	}
	r, e := s.storeRequest(base, m[1], nil, "POST")
	if e != nil {
		return e
	}
	var methods struct {
		Methods []struct {
			Name string `xml:"name,attr"`
			URL  string `xml:"url,attr"`
		} `xml:"method"`
	}
	if xml.Unmarshal(r.Body, &methods) != nil {
		return errors.New("invalid StoreFront authentication-method response")
	}
	for _, method := range methods.Methods {
		if method.Name == "CitrixAGBasic" {
			result, e := s.storeRequest(base, method.URL, nil, "POST")
			if e != nil {
				return e
			}
			var ar authResponse
			if xml.Unmarshal(result.Body, &ar) == nil && ar.Status != "" && ar.Status != "success" {
				return errors.New("StoreFront gateway SSO failed")
			}
			return nil
		}
	}
	return errors.New("StoreFront does not offer NetScaler gateway SSO")
}
func validateICA(b []byte) error {
	b = bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf})
	s := strings.ToLower(strings.ReplaceAll(string(b), "\r\n", "\n"))
	if !strings.Contains(s, "[applicationservers]") || !strings.Contains(s, "[wfclient]") {
		return errors.New("store did not return a valid ICA file (launch may be pending or denied)")
	}
	return nil
}
func (s *session) launchICA(base *url.URL, r resource) ([]byte, error) {
	// StoreFront Web API launch URLs are relative to the website root, not Resources/.
	root := *base
	if i := strings.LastIndex(strings.ToLower(root.Path), "/resources/"); i >= 0 {
		root.Path = root.Path[:i+1]
	}
	root.RawQuery = ""
	u, e := s.resolve(&root, r.LaunchURL)
	if e != nil {
		return nil, e
	}
	if r.LaunchStatusURL != "" {
		for attempt := 0; attempt < 30; attempt++ {
			status, e := s.storeRequest(&root, r.LaunchStatusURL, nil, "POST")
			if e != nil {
				return nil, e
			}
			var state struct {
				Status      string `json:"status"`
				PollTimeout int    `json:"pollTimeout"`
			}
			if json.Unmarshal(status.Body, &state) != nil {
				return nil, errors.New("invalid launch status response")
			}
			if state.Status == "success" {
				break
			}
			if state.Status != "retry" {
				return nil, errors.New("Citrix declined the resource launch")
			}
			if attempt == 29 {
				return nil, errors.New("desktop did not become ready")
			}
			delay := state.PollTimeout
			if delay < 1 {
				delay = 1
			}
			if delay > 30 {
				delay = 30
			}
			timer := time.NewTimer(time.Duration(delay) * time.Second)
			select {
			case <-timer.C:
			case <-s.ctx.Done():
				timer.Stop()
				return nil, s.ctx.Err()
			}
		}
	}
	q := u.Query()
	q.Set("displayNameDesktopTitle", r.Name)
	q.Set("IsUsingHttps", "Yes")
	u.RawQuery = q.Encode()
	out, e := s.storeRequest(&root, u.String(), nil, "GET")
	if e != nil {
		return nil, e
	}
	if e = validateICA(out.Body); e != nil {
		return nil, e
	}
	return out.Body, nil
}
func openICA(path, command string) error {
	if command != "" {
		cmd := exec.Command(command, path)
		if e := cmd.Start(); e != nil {
			return errors.New("cannot start configured ICA command")
		}
		go cmd.Wait()
		return nil
	}
	if runtime.GOOS == "linux" {
		for _, candidate := range []string{"wfica", "/opt/Citrix/ICAClient/wfica"} {
			if p, e := exec.LookPath(candidate); e == nil {
				cmd := exec.Command(p, path)
				if e = cmd.Start(); e != nil {
					return e
				}
				go cmd.Wait()
				return nil
			}
		}
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	if e := cmd.Run(); e != nil {
		return fmt.Errorf("ICA saved to %s; install Citrix Workspace or configure ica_command", path)
	}
	return nil
}
func writeICA(output string, b []byte) (string, error) {
	if output != "" {
		p, e := filepath.Abs(output)
		if e != nil {
			return "", e
		}
		return p, privateWrite(p, b)
	}
	// MkdirTemp avoids trusting an existing, possibly shared directory.
	dir, e := os.MkdirTemp("", "pomela-ica-*")
	if e != nil {
		return "", e
	}
	path := filepath.Join(dir, "launch.ica")
	if e = privateWrite(path, b); e != nil {
		os.RemoveAll(dir)
		return "", e
	}
	return path, nil
}
