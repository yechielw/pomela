package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

var configRE = regexp.MustCompile(`(?:\$Config|var\s+ServerData)\s*=\s*`)

func entraConfig(b []byte) map[string]any {
	for _, idx := range configRE.FindAllIndex(b, -1) {
		var cfg map[string]any
		if json.NewDecoder(bytes.NewReader(b[idx[1]:])).Decode(&cfg) == nil {
			return cfg
		}
	}
	return nil
}

type authResponse struct {
	Status, Result, StateContext, RedirectURL string
	Requirements                              struct {
		PostBack string
		Items    []struct {
			Credential struct{ ID, Type string }
			Input      struct{ Button string }
		} `xml:"Requirements>Requirement"`
	} `xml:"AuthenticationRequirements"`
}

func autoForm(b []byte) (string, url.Values, bool) {
	doc, e := html.Parse(bytes.NewReader(b))
	if e != nil {
		return "", nil, false
	}
	var form *html.Node
	var find func(*html.Node)
	find = func(n *html.Node) {
		if form != nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "form" {
			form = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			find(c)
		}
	}
	find(doc)
	if form == nil {
		return "", nil, false
	}
	action, method := "", ""
	for _, a := range form.Attr {
		if a.Key == "action" {
			action = a.Val
		}
		if a.Key == "method" {
			method = strings.ToLower(a.Val)
		}
	}
	if method != "post" {
		return "", nil, false
	}
	values := url.Values{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			name, value, typ := "", "", ""
			for _, a := range n.Attr {
				switch a.Key {
				case "name":
					name = a.Val
				case "value":
					value = a.Val
				case "type":
					typ = a.Val
				}
			}
			if name != "" && strings.EqualFold(typ, "hidden") {
				values.Add(name, value)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(form)
	return action, values, len(values) > 0
}

func (s *session) login(c credentials) (*response, error) {
	r, e := s.get(s.store, s.store.String())
	if e != nil {
		return nil, e
	}
	return s.walkLogin(c, r)
}

func (s *session) walkLogin(c credentials, r *response) (*response, error) {
	var e error
	passwordDone, mfaDone, gatewayStarted := false, false, false
	for hop := 0; hop < 30; hop++ {
		if e != nil {
			return nil, e
		}
		if r.Status >= 300 && r.Status < 400 {
			r, e = s.get(r.URL, r.Header.Get("Location"))
			continue
		}
		cfg := entraConfig(r.Body)
		if r.URL.Host == "login.microsoftonline.com" && cfg != nil {
			post := str(cfg, "urlPost")
			ft, ctx := str(cfg, "sFT"), str(cfg, "sCtx")
			if str(cfg, "urlGetCredentialType") != "" {
				if passwordDone {
					return nil, errors.New("Entra rejected the login or requested another password step; no automatic retry")
				}
				g, err := s.json(r.URL, str(cfg, "urlGetCredentialType"), map[string]any{"username": c.Username, "isOtherIdpSupported": true, "checkPhones": false, "isRemoteNGCSupported": false, "isFidoSupported": false, "originalRequest": ctx, "flowToken": ft}, nil)
				if err != nil {
					return nil, err
				}
				if creds, ok := g["Credentials"].(map[string]any); ok && str(creds, "FederationRedirectUrl") != "" {
					return nil, errors.New("this account uses an additional federated identity provider; unsupported headless flow")
				}
				// Account-discovery results are advisory (tenant/guest accounts can
				// report an unknown user). The password response is authoritative.
				ft = updated(g, "FlowToken", ft)
				r, e = s.form(r.URL, post, url.Values{"login": {c.Username}, "loginfmt": {c.Username}, "passwd": {c.Password}, "type": {"11"}, "LoginOptions": {"3"}, "ctx": {ctx}, "flowToken": {ft}, "canary": {str(cfg, "canary")}, "ps": {"2"}, "i19": {"1000"}})
				passwordDone = true
				continue
			}
			if str(cfg, "urlBeginAuth") != "" {
				if mfaDone {
					return nil, errors.New("Entra repeated the MFA challenge; no automatic retry")
				}
				mfaDone = true
				r, e = s.mfa(r, cfg, c)
				continue
			}
			if strings.HasSuffix(strings.TrimRight(post, "/"), "/kmsi") {
				r, e = s.form(r.URL, post, url.Values{"LoginOptions": {"3"}, "ctx": {ctx}, "flowToken": {ft}, "canary": {str(cfg, "canary")}, "i19": {"1000"}})
				continue
			}
			if code := fmt.Sprint(cfg["sErrorCode"]); code != "<nil>" && code != "" && code != "0" {
				return nil, errors.New("Entra returned a sign-in challenge or error; headless login cannot continue")
			}
		}
		if action, values, ok := autoForm(r.Body); ok {
			r, e = s.form(r.URL, action, values)
			continue
		}
		if r.URL.Host == s.store.Host {
			if bytes.Contains(r.Body, []byte("redirection_body_resources.js")) || bytes.Contains(r.Body, []byte("/vpn/init/redirect_body.js")) {
				if target := gatewayHTMLRedirect(r.Body); target != "" {
					r, e = s.get(r.URL, target)
					continue
				}
			}
			var ar authResponse
			if xml.Unmarshal(r.Body, &ar) == nil && ar.Status != "" {
				if ar.Status != "success" {
					return nil, errors.New("gateway authentication failed")
				}
				if ar.RedirectURL != "" {
					r, e = s.get(r.URL, ar.RedirectURL)
					continue
				}
				if ar.Requirements.PostBack != "" {
					v := url.Values{"StateContext": {ar.StateContext}}
					for _, q := range ar.Requirements.Items {
						if q.Input.Button == "" {
							return nil, errors.New("gateway requires an unsupported authentication factor")
						}
						v.Set(q.Credential.ID, q.Input.Button)
					}
					r, e = s.form(r.URL, ar.Requirements.PostBack, v)
					continue
				}
				if ar.Result == "success" {
					return r, nil
				}
			}
			// The logon UI normally starts this nFactor exchange with JavaScript.
			if strings.Contains(r.URL.Path, "/logon/") && !gatewayStarted {
				gatewayStarted = true
				r, e = s.form(s.store, "/nf/auth/getAuthenticationRequirements.do", url.Values{})
				continue
			}
			if !strings.Contains(r.URL.Path, "/logon/") {
				return r, nil
			}
		}
		return nil, errors.New("unsupported sign-in page (possible device compliance, CAPTCHA, password change or JavaScript-only challenge)")
	}
	return nil, errors.New("sign-in exceeded redirect/step limit")
}

func gatewayHTMLRedirect(b []byte) string {
	doc, err := html.Parse(bytes.NewReader(b))
	if err != nil {
		return ""
	}
	var visit func(*html.Node) string
	visit = func(n *html.Node) string {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" {
					return a.Val
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if target := visit(c); target != "" {
				return target
			}
		}
		return ""
	}
	return visit(doc)
}

func (s *session) mfa(r *response, cfg map[string]any, c credentials) (*response, error) {
	offered := false
	if proofs, ok := cfg["arrUserProofs"].([]any); ok {
		for _, p := range proofs {
			if m, ok := p.(map[string]any); ok && str(m, "authMethodId") == "PhoneAppOTP" {
				offered = true
			}
		}
	}
	if !offered {
		return nil, errors.New("Entra does not offer authenticator TOTP for this sign-in; headless login cannot satisfy the required MFA")
	}
	if c.TOTP == "" {
		return nil, errors.New("set totp in .env or POMELA_TOTP")
	}
	if _, e := totp(c.TOTP, time.Now()); e != nil {
		return nil, e
	}
	h := http.Header{}
	h.Set("canary", str(cfg, "apiCanary"))
	h.Set("client-request-id", str(cfg, "correlationId"))
	ctx, ft := str(cfg, "sCtx"), str(cfg, "sFT")
	b, e := s.json(r.URL, str(cfg, "urlBeginAuth"), map[string]any{"AuthMethodId": "PhoneAppOTP", "Method": "BeginAuth", "ctx": ctx, "flowToken": ft}, h)
	if e != nil {
		return nil, e
	}
	if b["Success"] != true {
		return nil, errors.New("Entra could not start TOTP authentication")
	}
	ctx, ft = updated(b, "Ctx", ctx), updated(b, "FlowToken", ft)
	// Avoid submitting a standard 30-second token just as it expires.
	if remaining := 30 - time.Now().Unix()%30; remaining < 5 {
		timer := time.NewTimer(time.Duration(remaining) * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		}
	}
	otp, e := totp(c.TOTP, time.Now())
	if e != nil {
		return nil, e
	}
	end, e := s.json(r.URL, str(cfg, "urlEndAuth"), map[string]any{"AuthMethodId": "PhoneAppOTP", "Method": "EndAuth", "ctx": ctx, "flowToken": ft, "SessionId": b["SessionId"], "AdditionalAuthData": otp, "PollCount": 1}, h)
	if e != nil {
		return nil, e
	}
	if end["Success"] != true || (str(end, "ResultValue") != "" && str(end, "ResultValue") != "Success") {
		return nil, errors.New("Entra rejected the TOTP code; check the seed and system clock")
	}
	ctx, ft = updated(end, "Ctx", ctx), updated(end, "FlowToken", ft)
	return s.form(r.URL, str(cfg, "urlPost"), url.Values{"type": {"19"}, "GeneralVerify": {"false"}, "request": {ctx}, "ctx": {ctx}, "flowToken": {ft}, "canary": {str(cfg, "canary")}, "mfaAuthMethod": {"PhoneAppOTP"}, "login": {c.Username}, "rememberMFA": {"false"}, "otc": {otp}})
}
