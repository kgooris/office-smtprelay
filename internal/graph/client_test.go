package graph

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type fakeMS struct {
	tokenCalls atomic.Int32
	sendCalls  atomic.Int32
	lastPath   string
	lastBody   string
	lastCT     string
	// sendStatus lets a test choose the answer of the sendMail endpoint.
	sendStatus func(call int32) (int, string)
}

func (f *fakeMS) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/tenant-1/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls.Add(1)
		_ = r.ParseForm()
		if r.Form.Get("client_secret") != "good-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x"}`)
			return
		}
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("scope") != "https://graph.microsoft.com/.default" {
			t.Errorf("unexpected token form: %v", r.Form)
		}
		_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
	})
	mux.HandleFunc("/v1.0/users/", func(w http.ResponseWriter, r *http.Request) {
		n := f.sendCalls.Add(1)
		f.lastPath = r.URL.EscapedPath()
		f.lastCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		f.lastBody = string(b)
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		status, body := http.StatusAccepted, ""
		if f.sendStatus != nil {
			status, body = f.sendStatus(n)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
	return mux
}

func newTestClient(t *testing.T, f *fakeMS, secret string) *Client {
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	return New(Credentials{TenantID: "tenant-1", ClientID: "app-1", ClientSecret: secret},
		WithEndpoints(srv.URL, srv.URL))
}

func TestSendMIME_OK(t *testing.T) {
	f := &fakeMS{}
	c := newTestClient(t, f, "good-secret")
	mime := []byte("From: a@example.com\r\nTo: b@example.org\r\nSubject: hi\r\n\r\nbody\r\n")
	if err := c.SendMIME(context.Background(), "printer@example.com", mime); err != nil {
		t.Fatal(err)
	}
	if f.lastPath != "/v1.0/users/printer@example.com/sendMail" && f.lastPath != "/v1.0/users/printer%40example.com/sendMail" {
		t.Errorf("path = %q", f.lastPath)
	}
	if f.lastCT != "text/plain" {
		t.Errorf("content-type = %q", f.lastCT)
	}
	got, err := base64.StdEncoding.DecodeString(f.lastBody)
	if err != nil || string(got) != string(mime) {
		t.Errorf("body is not the base64 MIME message: %v", err)
	}
}

func TestTokenIsCached(t *testing.T) {
	f := &fakeMS{}
	c := newTestClient(t, f, "good-secret")
	for i := 0; i < 3; i++ {
		if err := c.SendMIME(context.Background(), "a@example.com", []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.tokenCalls.Load(); n != 1 {
		t.Errorf("token requested %d times, want 1", n)
	}
}

func TestBadSecret(t *testing.T) {
	c := newTestClient(t, &fakeMS{}, "wrong")
	err := c.CheckCredentials(context.Background())
	var ge *Error
	if !errors.As(err, &ge) || ge.Status != 401 || ge.Code != "invalid_client" {
		t.Fatalf("err = %#v", err)
	}
	if strings.ContainsAny(ge.Message, "\r\n") {
		t.Errorf("message must be a single line: %q", ge.Message)
	}
}

func TestGraphErrorParsed(t *testing.T) {
	f := &fakeMS{sendStatus: func(int32) (int, string) {
		return http.StatusForbidden, `{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}`
	}}
	c := newTestClient(t, f, "good-secret")
	err := c.SendMIME(context.Background(), "a@example.com", []byte("x"))
	var ge *Error
	if !errors.As(err, &ge) || ge.Status != 403 || ge.Code != "ErrorAccessDenied" || ge.Temporary() {
		t.Fatalf("err = %#v", err)
	}
}

func TestThrottlingIsTemporary(t *testing.T) {
	f := &fakeMS{sendStatus: func(int32) (int, string) { return http.StatusTooManyRequests, `{}` }}
	c := newTestClient(t, f, "good-secret")
	err := c.SendMIME(context.Background(), "a@example.com", []byte("x"))
	var ge *Error
	if !errors.As(err, &ge) || !ge.Temporary() {
		t.Fatalf("err = %#v", err)
	}
}

func TestRetryOnceOn401(t *testing.T) {
	f := &fakeMS{}
	f.sendStatus = func(call int32) (int, string) {
		if call == 1 {
			return http.StatusUnauthorized, ""
		}
		return http.StatusAccepted, ""
	}
	c := newTestClient(t, f, "good-secret")
	if err := c.SendMIME(context.Background(), "a@example.com", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if f.tokenCalls.Load() != 2 {
		t.Errorf("token calls = %d, want 2 (one refresh)", f.tokenCalls.Load())
	}
}
