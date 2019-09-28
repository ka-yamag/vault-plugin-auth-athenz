package athenz

import (
	"context"

	"github.com/yahoojapan/athenz-authorizer/role"
)

// Athenz is interface for athenz setting or daemon
type Athenz interface {
	Run(context.Context)
	VerifyToken(context.Context, string) (*role.RoleToken, error)
}
