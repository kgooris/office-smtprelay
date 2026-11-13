package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	_ "time/tzdata" // lets TZ=Europe/Brussels work in a minimal container image

	"github.com/emersion/go-smtp"

	"github.com/kgooris/office-smtprelay/internal/config"
	"github.com/kgooris/office-smtprelay/internal/notify"
	"github.com/kgooris/office-smtprelay/internal/relay"
	"github.com/kgooris/office-smtprelay/internal/store"
	"github.com/kgooris/office-smtprelay/internal/tlsutil"
	"github.com/kgooris/office-smtprelay/internal/web"
)

func openStore(cfg config.Config) (*store.Store, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("data directory: %w", err)
	}
	key, err := store.LoadOrCreateKey(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(cfg.DataDir, "relay.db"), key)
}

func runServe() error {
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	globalMin := func() uint16 {
		if v := tlsutil.ParseVersion(st.TLSMin()); v != 0 {
			return v
		}
		return cfg.TLSMinVersion
	}
	clientMin := func(ip netip.Addr) uint16 { return tlsutil.ParseVersion(st.PolicyForIP(ip).TLS.MinVersion) }
	tlsMgr, err := tlsutil.NewManager(cfg.DataDir, cfg.TLSCert, cfg.TLSKey, append([]string{cfg.Hostname}, cfg.TLSNames...), globalMin, clientMin)
	if err != nil {
		return fmt.Errorf("TLS: %w", err)
	}

	sender := &lazySender{st: st}
	alerts := notify.New(st, sender, cfg.Lang, log.Default())
	alerts.LangFn = func() string { return st.EffectiveLang(cfg.Lang) }
	be := relay.NewBackend(relay.Config{
		Hostname:        cfg.Hostname,
		MaxMessageBytes: int64(cfg.MaxMessageMB) << 20,
		Limits: func() relay.Limits {
			return relay.Limits{MaxMessageBytes: st.EffectiveMaxMessageBytes(cfg.MaxMessageMB), MaxConnsPerIP: st.General().MaxConnsPerIP}
		},
	}, st, sender, notify.Recorder{Inner: st, N: alerts})
	srv := smtp.NewServer(be)
	be.ConfigureServer(srv)
	srv.Addr = cfg.SMTPAddr
	srv.TLSConfig = tlsMgr.Config()
	srv.ErrorLog = log.Default()
	conn := newConnControl(tlsMgr, be)
	defer conn.Close()
	if err := conn.ApplyPorts(st.ExtraPorts()); err != nil {
		log.Printf("WARNING: extra SMTP listener: %v", err)
	}

	ui, err := web.New(web.Deps{Store: st, Mailer: sender, Config: cfg, Version: version, Logger: log.Default(), Relay: be, Notifier: alerts, Conn: conn})
	if err != nil {
		return fmt.Errorf("web UI: %w", err)
	}
	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           ui.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second, // the test-mail page waits for Microsoft
		IdleTimeout:       2 * time.Minute,
	}

	clients, _ := st.ListClients()
	_, graphOK, _ := st.GraphCredentials()
	log.Printf("office-smtprelay %s: SMTP on %s, HTTP on %s, %d client(s) registered", version, cfg.SMTPAddr, cfg.HTTPAddr, len(clients))
	if !graphOK {
		log.Printf("WARNING: the Microsoft 365 connection is not configured yet; mail will be refused until it is (see: office-smtprelay graph set)")
	}
	if globalMin() < 0x0303 {
		log.Printf("WARNING: legacy TLS versions are allowed for all devices; use only for old devices on a trusted network")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 2)
	go func() { errc <- fmt.Errorf("SMTP server: %w", srv.ListenAndServe()) }()
	go func() { errc <- fmt.Errorf("HTTP server: %w", httpSrv.ListenAndServe()) }()
	go pruneLoop(ctx, st, func() int { return st.EffectiveRetentionDays(cfg.EventRetentionDays) })
	go alerts.ExpiryLoop(ctx)

	select {
	case <-ctx.Done():
		log.Printf("shutting down")
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, smtp.ErrServerClosed) {
			stop()
			_ = srv.Close()
			_ = httpSrv.Close()
			return err
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return srv.Close()
}

func pruneLoop(ctx context.Context, st *store.Store, daysFn func() int) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		if n, err := st.PruneEvents(time.Duration(daysFn())*24*time.Hour, 50000); err != nil {
			log.Printf("event pruning failed: %v", err)
		} else if n > 0 {
			log.Printf("pruned %d old event(s)", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// runHealthcheck is used by the container HEALTHCHECK (the image has no curl).
func runHealthcheck() error {
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(cfg.HTTPAddr)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}
