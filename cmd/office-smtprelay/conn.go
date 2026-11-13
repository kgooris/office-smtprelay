package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/emersion/go-smtp"

	"github.com/kgooris/office-smtprelay/internal/relay"
	"github.com/kgooris/office-smtprelay/internal/store"
	"github.com/kgooris/office-smtprelay/internal/tlsutil"
)

// connControl manages the certificate and the optional extra SMTP listeners
// while the relay runs. The web UI uses it through web.Connection.
type connControl struct {
	mgr *tlsutil.Manager
	be  *relay.Backend

	mu       sync.Mutex
	implicit *extraListener
	legacy   *extraListener
}

type extraListener struct {
	port int
	srv  *smtp.Server
}

func newConnControl(mgr *tlsutil.Manager, be *relay.Backend) *connControl {
	return &connControl{mgr: mgr, be: be}
}

// CertInfo describes the certificate in use.
func (c *connControl) CertInfo() tlsutil.CertInfo { return c.mgr.Info() }

// UploadCert replaces the certificate.
func (c *connControl) UploadCert(certPEM, keyPEM []byte) error { return c.mgr.Upload(certPEM, keyPEM) }

// RegenerateCert creates a new self-signed certificate.
func (c *connControl) RegenerateCert(names []string) error { return c.mgr.Regenerate(names) }

// Listening returns the ports of the extra listeners that are running (0 = off).
func (c *connControl) Listening() (implicit, legacy int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.implicit != nil {
		implicit = c.implicit.port
	}
	if c.legacy != nil {
		legacy = c.legacy.port
	}
	return implicit, legacy
}

// ApplyPorts starts, stops or moves the extra listeners so that they match p.
// If a port cannot be opened the error says which one; the others still apply.
func (c *connControl) ApplyPorts(p store.Ports) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	c.implicit = c.reconcile(c.implicit, p.Implicit, "implicit TLS", c.startImplicit, keep)
	c.legacy = c.reconcile(c.legacy, p.Legacy, "no encryption", c.startLegacy, keep)
	return first
}

func (c *connControl) reconcile(cur *extraListener, port int, name string, start func(int) (*extraListener, error), keep func(error)) *extraListener {
	if cur != nil && cur.port == port {
		return cur
	}
	if cur != nil {
		_ = cur.srv.Close()
		log.Printf("SMTP listener (%s) on port %d stopped", name, cur.port)
	}
	if port == 0 {
		return nil
	}
	l, err := start(port)
	if err != nil {
		keep(fmt.Errorf("port %d (%s): %w", port, name, err))
		return nil
	}
	log.Printf("SMTP listener (%s) started on port %d", name, port)
	return l
}

func (c *connControl) startImplicit(port int) (*extraListener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	srv := smtp.NewServer(c.be)
	c.be.ConfigureServer(srv)
	srv.ErrorLog = log.Default()
	go func() { _ = srv.Serve(tls.NewListener(ln, c.mgr.Config())) }()
	return &extraListener{port: port, srv: srv}, nil
}

func (c *connControl) startLegacy(port int) (*extraListener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	srv := smtp.NewServer(c.be.ForLegacy())
	c.be.ConfigureServer(srv)
	srv.Backend = c.be.ForLegacy()
	srv.AllowInsecureAuth = true // only devices whose rules allow it can sign in here
	srv.ErrorLog = log.Default()
	go func() { _ = srv.Serve(ln) }()
	return &extraListener{port: port, srv: srv}, nil
}

// Close stops the extra listeners.
func (c *connControl) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range []*extraListener{c.implicit, c.legacy} {
		if l != nil {
			_ = l.srv.Close()
		}
	}
	c.implicit, c.legacy = nil, nil
}
