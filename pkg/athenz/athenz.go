package athenz

import (
	"context"

	"github.com/yahoojapan/athenz-policy-updater/role"
)

// Athenz is interface for athenz dameon
type Athenz interface {
	Run(context.Context)
	VerifyToken(context.Context, string) (*role.RoleToken, error)
}
