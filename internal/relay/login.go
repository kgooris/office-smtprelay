package relay

import "github.com/emersion/go-sasl"

// loginServer implements the (non-standard but widespread) LOGIN SASL
// mechanism that many printers and scanners use instead of PLAIN.
type loginServer struct {
	auth  func(user, pass string) error
	state int
	user  string
}

var _ sasl.Server = (*loginServer)(nil)

func (s *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch s.state {
	case 0:
		if len(response) > 0 { // username sent as initial response
			s.user = string(response)
			s.state = 2
			return []byte("Password:"), false, nil
		}
		s.state = 1
		return []byte("Username:"), false, nil
	case 1:
		s.user = string(response)
		s.state = 2
		return []byte("Password:"), false, nil
	default:
		return nil, true, s.auth(s.user, string(response))
	}
}
