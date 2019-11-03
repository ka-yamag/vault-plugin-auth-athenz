package athenz

import (
	"context"

	"github.com/yahoo/athenz/clients/go/zts"
)

// MockAthenz is a mock for Athenz
type MockAthenz struct {
	InitErr        error
	RoleToken      *zts.RoleToken
	VerifyTokenErr error
}

// SetMockAthenz sets the specify mock structure
func SetMockAthenz(m *MockAthenz) {
	validator = m
}

// Init is ...
func (m *MockAthenz) Init(context.Context) error {
	return m.InitErr
}

// Start is ...
func (m *MockAthenz) Start(context.Context) {
}

// VerifyToken is ...
func (m *MockAthenz) VerifyToken(context.Context, string, string) (*zts.RoleToken, error) {
	return m.RoleToken, m.VerifyTokenErr
}
