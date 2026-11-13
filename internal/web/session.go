package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"

	"github.com/kgooris/office-smtprelay/internal/store"
)

const (
	defaultIdle     = 30 * time.Minute
	sessionAbsolute = 12 * time.Hour
	cookieSession   = "sid"
	cookiePre       = "pre" // CSRF token for the login and setup forms (no session yet)
	cookieLang      = "lang"
)

type session struct {
	csrf     string
	created  time.Time
	last     time.Time
	userID   int64
	username string
	role     string
}

func (s *session) admin() bool { return s.role == store.RoleAdmin }

// sessions is an in-memory session store. Sessions end when the process
// restarts, which simply means signing in again.
type sessions struct {
	mu   sync.Mutex
	m    map[string]*session
	now  func() time.Time
	idle func() time.Duration // how long a session may stay unused; changeable in the UI
}

func newSessions() *sessions {
	return &sessions{m: map[string]*session{}, now: time.Now, idle: func() time.Duration { return defaultIdle }}
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("web: no randomness available: " + err.Error()) // cannot continue safely
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *sessions) create(u store.User) (string, *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, v := range s.m { // purge expired sessions
		if s.expired(v, now) {
			delete(s.m, id)
		}
	}
	id := randToken(32)
	v := &session{csrf: randToken(24), created: now, last: now, userID: u.ID, username: u.Username, role: u.Role}
	s.m[id] = v
	return id, v
}

func (s *sessions) expired(v *session, now time.Time) bool {
	return now.Sub(v.last) > s.idle() || now.Sub(v.created) > sessionAbsolute
}

// get returns the session for id and refreshes its idle timer.
func (s *sessions) get(id string) (*session, bool) {
	if id == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[id]
	if !ok {
		return nil, false
	}
	now := s.now()
	if s.expired(v, now) {
		delete(s.m, id)
		return nil, false
	}
	v.last = now
	return v, true
}

func (s *sessions) destroy(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

// peek returns the session without refreshing its idle timer (for drawing the menu).
func (s *sessions) peek(id string) (*session, bool) {
	if id == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[id]
	if !ok || s.expired(v, s.now()) {
		return nil, false
	}
	return v, true
}

// destroyUser signs a user out everywhere (after a password or role change).
func (s *sessions) destroyUser(userID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, v := range s.m {
		if v.userID == userID {
			delete(s.m, id)
		}
	}
}

// destroyAll signs everybody out (after a password change).
func (s *sessions) destroyAll() {
	s.mu.Lock()
	s.m = map[string]*session{}
	s.mu.Unlock()
}

func tokensEqual(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
