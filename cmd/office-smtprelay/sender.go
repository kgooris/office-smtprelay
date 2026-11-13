package main

import (
	"context"
	"sync"

	"github.com/kgooris/office-smtprelay/internal/graph"
	"github.com/kgooris/office-smtprelay/internal/store"
)

// lazySender sends through Graph using the credentials currently saved in
// the store. Changing the Microsoft connection (UI or CLI) takes effect on
// the next message without a restart.
type lazySender struct {
	st      *store.Store
	options []graph.Option // for tests

	mu     sync.Mutex
	creds  graph.Credentials
	client *graph.Client
}

func (l *lazySender) current() (*graph.Client, error) {
	creds, ok, err := l.st.GraphCredentials()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &graph.Error{Status: 401, Code: "not_configured", Message: "the Microsoft 365 connection is not configured"}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.client == nil || creds != l.creds {
		l.client, l.creds = graph.New(creds, l.options...), creds
	}
	return l.client, nil
}

// CheckCredentials validates the saved Microsoft connection (token request only).
func (l *lazySender) CheckCredentials(ctx context.Context) error {
	c, err := l.current()
	if err != nil {
		return err
	}
	return c.CheckCredentials(ctx)
}

func (l *lazySender) SendMIME(ctx context.Context, sender string, mime []byte) error {
	c, err := l.current()
	if err != nil {
		return err
	}
	return c.SendMIME(ctx, sender, mime)
}
