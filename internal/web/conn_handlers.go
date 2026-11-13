package web

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/kgooris/office-smtprelay/internal/store"
	"github.com/kgooris/office-smtprelay/internal/tlsutil"
)

// Connection is what the UI needs to manage the certificate and the extra SMTP
// listeners of the running relay.
type Connection interface {
	CertInfo() tlsutil.CertInfo
	UploadCert(certPEM, keyPEM []byte) error
	RegenerateCert(names []string) error
	// ApplyPorts starts, stops or moves the extra listeners.
	ApplyPorts(p store.Ports) error
	// Listening returns the ports of the extra listeners that are running (0 = off).
	Listening() (implicit, legacy int)
}

// noConn is used when the UI runs without a relay (tests, tools).
type noConn struct{}

func (noConn) CertInfo() tlsutil.CertInfo        { return tlsutil.CertInfo{} }
func (noConn) UploadCert(_, _ []byte) error      { return errors.New("not available") }
func (noConn) RegenerateCert([]string) error     { return errors.New("not available") }
func (noConn) ApplyPorts(store.Ports) error      { return nil }
func (noConn) Listening() (implicit, legacy int) { return 0, 0 }

type connData struct {
	Cert                   tlsutil.CertInfo
	CertAvail              bool
	CertManaged            bool // set with environment variables
	TLSMin, DefMin         string
	Implicit, Legacy       string
	RunImplicit, RunLegacy int
	MainPort               string
	NamesText              string
	Snippet                string
}

func versionText(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return "?"
}

func (s *Server) connData() connData {
	info := s.d.Conn.CertInfo()
	p := s.d.Store.ExtraPorts()
	ri, rl := s.d.Conn.Listening()
	_, port, _ := net.SplitHostPort(s.d.Config.SMTPAddr)
	d := connData{
		Cert: info, CertAvail: info.Fingerprint != "", CertManaged: info.Source == tlsutil.SourceEnvironment,
		TLSMin: s.d.Store.TLSMin(), DefMin: versionText(s.d.Config.TLSMinVersion),
		Implicit: portText(p.Implicit), Legacy: portText(p.Legacy), RunImplicit: ri, RunLegacy: rl, MainPort: port,
		NamesText: strings.Join(info.Names, ", "),
		Snippet:   snippet(portText(p.Implicit), portText(p.Legacy)),
	}
	return d
}

func portText(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func (s *Server) connView(r *http.Request, sd *session) view {
	v := view{Nav: true, Active: "connection", CSRF: sd.csrf, Data: s.connData()}
	s.flashFromQuery(r, &v)
	return v
}

func (s *Server) connPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	s.render(w, r, http.StatusOK, "conn", s.connView(r, sd))
}

func (s *Server) connFail(w http.ResponseWriter, r *http.Request, sd *session, key string, detail string) {
	v := s.connView(r, sd)
	v.Flash, v.FlashKind = s.tr(r, key), "err"
	if detail != "" {
		v.Flash = s.tr(r, key, detail)
	}
	s.render(w, r, http.StatusBadRequest, "conn", v)
}

func (s *Server) connTLSMin(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	if err := s.d.Store.SetTLSMin(r.PostFormValue("tls_min")); err != nil {
		s.connFail(w, r, sd, "conn.err_generic", err.Error())
		return
	}
	s.d.Logger.Printf("web UI: minimum TLS version set to %q", r.PostFormValue("tls_min"))
	http.Redirect(w, r, "/connection?ok=conn_saved", http.StatusSeeOther)
}

func (s *Server) connPorts(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	_, mainPort, _ := net.SplitHostPort(s.d.Config.SMTPAddr)
	mp, _ := strconv.Atoi(mainPort)
	p := store.Ports{Implicit: atoiLoose(r.PostFormValue("implicit")), Legacy: atoiLoose(r.PostFormValue("legacy"))}
	if err := s.d.Store.SetExtraPorts(p, mp); err != nil {
		s.connFail(w, r, sd, "conn.err_ports", "")
		return
	}
	if err := s.d.Conn.ApplyPorts(p); err != nil {
		s.connFail(w, r, sd, "conn.err_bind", err.Error())
		return
	}
	http.Redirect(w, r, "/connection?ok=conn_saved", http.StatusSeeOther)
}

func readUpload(r *http.Request, field string) ([]byte, error) {
	f, _, err := r.FormFile(field)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 256<<10))
}

func (s *Server) connCert(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	certPEM, err1 := readUpload(r, "cert")
	keyPEM, err2 := readUpload(r, "key")
	if err1 != nil || err2 != nil {
		s.connFail(w, r, sd, "conn.err_files", "")
		return
	}
	if err := s.d.Conn.UploadCert(certPEM, keyPEM); err != nil {
		s.connFail(w, r, sd, "conn.err_cert", err.Error())
		return
	}
	s.d.Logger.Printf("web UI: TLS certificate replaced by an uploaded one")
	http.Redirect(w, r, "/connection?ok=conn_cert_saved", http.StatusSeeOther)
}

func (s *Server) connRegenerate(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	if err := s.d.Conn.RegenerateCert(splitEntries(r.PostFormValue("names"))); err != nil {
		s.connFail(w, r, sd, "conn.err_cert", err.Error())
		return
	}
	s.d.Logger.Printf("web UI: new self-signed TLS certificate created")
	http.Redirect(w, r, "/connection?ok=conn_cert_saved", http.StatusSeeOther)
}

// snippet returns the docker compose "ports:" lines the administrator has to
// add for the extra listeners.
func snippet(implicit, legacy string) string {
	var b strings.Builder
	if implicit != "" {
		fmt.Fprintf(&b, "      - \"465:%s\"   # SMTP over TLS\n", implicit)
	}
	if legacy != "" {
		fmt.Fprintf(&b, "      - \"2526:%s\"  # no encryption (old devices only)\n", legacy)
	}
	return b.String()
}
