package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type session struct {
	client  *http.Client
	store   *url.URL
	ctx     context.Context
	verbose bool
}
type response struct {
	URL    *url.URL
	Header http.Header
	Body   []byte
	Status int
}

func newSession(ctx context.Context, store string, verbose bool) (*session, error) {
	if !strings.Contains(store, "://") {
		store = "https://" + store
	}
	u, e := url.Parse(store)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("store must be an HTTPS URL without credentials, query or fragment")
	}
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return &session{client: &http.Client{Jar: jar, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, store: u, ctx: ctx, verbose: verbose}, nil
}
func (s *session) allowed(u *url.URL) bool {
	return u.Scheme == "https" && u.User == nil && (u.Host == s.store.Host || u.Host == "login.microsoftonline.com")
}
func (s *session) resolve(base *url.URL, path string) (*url.URL, error) {
	u, e := base.Parse(path)
	if e != nil || !s.allowed(u) {
		return nil, errors.New("refusing redirect or form submission outside the store and login.microsoftonline.com")
	}
	return u, nil
}
func (s *session) request(method string, u *url.URL, body []byte, contentType string, headers http.Header) (*response, error) {
	if !s.allowed(u) {
		return nil, errors.New("untrusted request destination")
	}
	req, e := http.NewRequestWithContext(s.ctx, method, u.String(), bytes.NewReader(body))
	if e != nil {
		return nil, errors.New("invalid request")
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if s.verbose {
		fmt.Printf("%s %s%s\n", method, u.Host, u.EscapedPath())
	}
	r, e := s.client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("request to %s failed (network, TLS or timeout)", u.Host)
	}
	defer r.Body.Close()
	// NetScaler uses a legacy full-weekday, four-digit-year cookie expiry
	// that net/http does not recognize. Expired logout cookies must not
	// accidentally become session cookies and bounce the login back to /.
	for _, cookie := range r.Cookies() {
		if cookie.RawExpires != "" && cookie.Expires.IsZero() {
			for _, layout := range []string{"Monday, 02-Jan-2006 15:04:05 MST", "Monday, 02 Jan 2006 15:04:05 MST"} {
				if expiry, err := time.Parse(layout, cookie.RawExpires); err == nil {
					cookie.Expires = expiry
					s.client.Jar.SetCookies(u, []*http.Cookie{cookie})
					break
				}
			}
		}
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024+1))
	if e != nil {
		return nil, errors.New("cannot read response")
	}
	if len(b) > 8*1024*1024 {
		return nil, errors.New("response exceeds 8 MiB")
	}
	if r.StatusCode >= 400 {
		return nil, fmt.Errorf("%s returned HTTP %d", u.Host, r.StatusCode)
	}
	return &response{u, r.Header, b, r.StatusCode}, nil
}
func (s *session) get(base *url.URL, path string) (*response, error) {
	u, e := s.resolve(base, path)
	if e != nil {
		return nil, e
	}
	return s.request("GET", u, nil, "", nil)
}
func (s *session) form(base *url.URL, path string, v url.Values) (*response, error) {
	u, e := s.resolve(base, path)
	if e != nil {
		return nil, e
	}
	return s.request("POST", u, []byte(v.Encode()), "application/x-www-form-urlencoded", nil)
}
func (s *session) json(base *url.URL, path string, v any, h http.Header) (map[string]any, error) {
	u, e := s.resolve(base, path)
	if e != nil {
		return nil, e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	r, e := s.request("POST", u, b, "application/json", h)
	if e != nil {
		return nil, e
	}
	var out map[string]any
	if json.Unmarshal(r.Body, &out) != nil {
		return nil, errors.New("expected JSON authentication response")
	}
	return out, nil
}
func str(m map[string]any, k string) string { v, _ := m[k].(string); return v }
func updated(m map[string]any, k, old string) string {
	if v := str(m, k); v != "" {
		return v
	}
	return old
}
