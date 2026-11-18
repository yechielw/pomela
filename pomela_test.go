package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func reply(r *http.Request, status int, body string, h http.Header) *http.Response {
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}
func configHTML(v map[string]any) string {
	b, _ := json.Marshal(v)
	return "<script>$Config=" + string(b) + ";</script>"
}

func TestHeadlessEndToEnd(t *testing.T) {
	s, e := newSession(context.Background(), "https://store.test", false)
	if e != nil {
		t.Fatal(e)
	}
	passwordPosts, mfaPosts, listCalls, statusCalls := 0, 0, 0, 0
	s.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		form := func() {
			if e := r.ParseForm(); e != nil {
				t.Fatal(e)
			}
		}
		if r.URL.Host == "store.test" && strings.Contains(r.URL.Path, "/Citrix/") && r.Method == "POST" && !strings.HasSuffix(r.URL.Path, "Home/Configuration") {
			if r.Header.Get("Csrf-Token") != "csrf" {
				t.Fatal("missing CSRF header")
			}
		}
		switch r.URL.Path {
		case "", "/":
			return reply(r, 302, "", http.Header{"Location": {"/logon/start"}, "Set-Cookie": {"NSC_USER=xyz;Path=/;expires=Wednesday, 09-Nov-1999 23:12:40 GMT;Secure"}}), nil
		case "/logon/start":
			if r.Header.Get("Cookie") != "" {
				t.Fatal("expired gateway cookie was retained")
			}
			return reply(r, 200, "<html>gateway</html>", nil), nil
		case "/nf/auth/getAuthenticationRequirements.do":
			return reply(r, 200, `<AuthenticateResponse><Status>success</Status><AuthenticationRequirements><PostBack>/nf/auth/doAuthentication.do</PostBack><Requirements><Requirement><Credential><ID>loginBtn</ID></Credential><Input><Button>Log On</Button></Input></Requirement></Requirements></AuthenticationRequirements></AuthenticateResponse>`, nil), nil
		case "/nf/auth/doAuthentication.do":
			form()
			if r.Form.Get("loginBtn") != "Log On" {
				t.Fatal("missing gateway button")
			}
			return reply(r, 200, `<AuthenticateResponse><Status>success</Status><RedirectURL>https://login.microsoftonline.com/tenant/saml2</RedirectURL></AuthenticateResponse>`, nil), nil
		case "/tenant/saml2":
			return reply(r, 200, configHTML(map[string]any{"urlGetCredentialType": "/common/GetCredentialType", "sFT": "ft", "sCtx": "ctx", "urlPost": "/tenant/login", "canary": "canary"}), nil), nil
		case "/common/GetCredentialType":
			return reply(r, 200, `{"FlowToken":"newft","IfExistsResult":0}`, nil), nil
		case "/tenant/login":
			passwordPosts++
			form()
			if r.Form.Get("passwd") != "password" || r.Form.Get("flowToken") != "newft" {
				t.Fatal("bad password form")
			}
			return reply(r, 200, configHTML(map[string]any{"sFT": "ft", "sCtx": "ctx", "urlBeginAuth": "/common/SAS/BeginAuth", "urlEndAuth": "/common/SAS/EndAuth", "urlPost": "/common/SAS/ProcessAuth", "arrUserProofs": []map[string]any{{"authMethodId": "PhoneAppOTP"}}}), nil), nil
		case "/common/SAS/BeginAuth":
			return reply(r, 200, `{"Success":true,"SessionId":"session","Ctx":"ctx2","FlowToken":"ft2"}`, nil), nil
		case "/common/SAS/EndAuth":
			mfaPosts++
			var v map[string]any
			json.NewDecoder(r.Body).Decode(&v)
			if str(v, "SessionId") != "session" || len(str(v, "AdditionalAuthData")) != 6 {
				t.Fatal("bad MFA payload")
			}
			return reply(r, 200, `{"Success":true,"ResultValue":"Success","Ctx":"ctx3","FlowToken":"ft3"}`, nil), nil
		case "/common/SAS/ProcessAuth":
			form()
			if r.Form.Get("ctx") != "ctx3" || r.Form.Get("flowToken") != "ft3" {
				t.Fatal("lost MFA state")
			}
			return reply(r, 200, `<form method="post" action="https://store.test/cgi/samlauth"><input value="assertion&amp;value" type="hidden" name="SAMLResponse"></form>`, nil), nil
		case "/cgi/samlauth":
			form()
			if r.Form.Get("SAMLResponse") != "assertion&value" {
				t.Fatal("SAML assertion parsing")
			}
			return reply(r, 302, "", http.Header{"Location": {"/cgi/setclient"}}), nil
		case "/cgi/setclient":
			return reply(r, 200, `<script src="/vpn/init/redirect_body.js"></script><a id="redirect_link" href="/Citrix/TestWeb/">here</a>`, nil), nil
		case "/Citrix/TestWeb/":
			return reply(r, 200, "<html>Workspace</html>", nil), nil
		case "/Citrix/TestWeb/Home/Configuration":
			return reply(r, 200, `<clientSettings><storeProxy><resourcesProxy listURL="Resources/List"/></storeProxy></clientSettings>`, http.Header{"Set-Cookie": {"CsrfToken=csrf;Path=/Citrix/TestWeb/;Secure"}}), nil
		case "/Citrix/TestWeb/Resources/List":
			listCalls++
			if listCalls == 1 {
				return reply(r, 200, `{"unauthorized":true}`, http.Header{"Citrixwebreceiver-Authenticate": {`reason="notoken", location="Authentication/GetAuthMethods"`}}), nil
			}
			return reply(r, 200, `{"resources":[{"id":"desktop","name":"My Desktop","clienttypes":["ica30"],"launchurl":"Resources/LaunchIca/id.ica","launchstatusurl":"Resources/GetLaunchStatus/id"},{"id":"content","name":"Link","clienttypes":["content"],"launchurl":"unused"}]}`, nil), nil
		case "/Citrix/TestWeb/Authentication/GetAuthMethods":
			return reply(r, 200, `<authMethods><method name="CitrixAGBasic" url="GatewayAuth/Login"/></authMethods>`, nil), nil
		case "/Citrix/TestWeb/GatewayAuth/Login":
			return reply(r, 200, `<AuthenticationStatus><Result>success</Result></AuthenticationStatus>`, http.Header{"Set-Cookie": {"CtxsAuthId=auth;Path=/Citrix/TestWeb/;Secure"}}), nil
		case "/Citrix/TestWeb/Resources/GetLaunchStatus/id":
			statusCalls++
			return reply(r, 200, `{"status":"success"}`, nil), nil
		case "/Citrix/TestWeb/Resources/LaunchIca/id.ica":
			if r.URL.Query().Get("CsrfToken") != "csrf" || r.URL.Query().Get("IsUsingHttps") != "Yes" {
				t.Fatal("missing ICA CSRF query")
			}
			return reply(r, 200, "[WFClient]\r\nVersion=2\r\n[ApplicationServers]\r\nDesktop=\r\n", nil), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL)
			return nil, fmt.Errorf("unexpected request")
		}
	})
	final, e := s.login(credentials{"user@example.org", "password", "JBSWY3DPEHPK3PXP"})
	if e != nil {
		t.Fatal(e)
	}
	rr, base, e := s.resources(final, "")
	if e != nil {
		t.Fatal(e)
	}
	if len(rr) != 1 {
		t.Fatalf("ICA resources: %d", len(rr))
	}
	b, e := s.launchICA(base, rr[0])
	if e != nil {
		t.Fatal(e)
	}
	if e = validateICA(b); e != nil {
		t.Fatal(e)
	}
	if passwordPosts != 1 || mfaPosts != 1 || listCalls != 2 || statusCalls != 1 {
		t.Fatal("unexpected repeated authentication or launch")
	}
}

func TestTOTPVectors(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, v := range []struct {
		at   int64
		want string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		got, e := totp("otpauth://totp/test?secret="+seed+"&digits=8", time.Unix(v.at, 0))
		if e != nil || got != v.want {
			t.Fatalf("at %d: %s %v", v.at, got, e)
		}
	}
	if _, e := totp("not-base32!", time.Now()); e == nil {
		t.Fatal("invalid seed accepted")
	}
}
func TestDestinationAndFiles(t *testing.T) {
	s, _ := newSession(context.Background(), "https://store.test", false)
	for _, target := range []string{"http://store.test/", "https://login.microsoftonline.com.evil.test/", "https://user:pass@store.test/", "https://store.test:443/"} {
		if _, e := s.resolve(s.store, target); e == nil {
			t.Fatalf("accepted %s", target)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if e := saveConfig(path, config{Store: "https://store.test", Machine: "desktop"}); e != nil {
		t.Fatal(e)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("config is not private")
	}
	if _, e := choose([]resource{{ID: "1", Name: "Same"}, {ID: "2", Name: "Same"}}, "Same", false); e == nil {
		t.Fatal("ambiguous machine selected")
	}
	if e := validateICA([]byte("<html>login</html>")); e == nil {
		t.Fatal("HTML accepted as ICA")
	}
}
