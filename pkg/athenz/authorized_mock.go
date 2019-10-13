package athenz

import (
	"context"
	"crypto/x509"
	"errors"
	"time"
)

// MockAuthorizerd is a mock for Authorizerd
type MockAuthorizerd struct {
	initErr            error
	verifyRoleTokenErr error
	startErr           string
}

// Init is
func (m *MockAuthorizerd) Init(ctx context.Context) error {
	return m.initErr
}

func (m *MockAuthorizerd) Start(ctx context.Context) <-chan error {
	if m.startErr != "" {
		ch := make(chan error, 1)
		go func() {
			time.Sleep(time.Millisecond * 20)
			ch <- errors.New(m.startErr)
		}()
		return ch
	}

	return nil
}

func (m *MockAuthorizerd) VerifyRoleToken(ctx context.Context, tok, act, res string) error {
	return m.verifyRoleTokenErr
}

func (m *MockAuthorizerd) VerifyRoleJWT(ctx context.Context, tok, act, res string) error {
	return nil
}

func (m *MockAuthorizerd) VerifyRoleCert(ctx context.Context, peerCerts []*x509.Certificate, act, res string) error {
	return nil
}

func (m *MockAuthorizerd) GetPolicyCache(ctx context.Context) map[string]interface{} {
	return nil
}
