package athenz

import (
	"context"
	"fmt"

	"github.com/katyamag/vault-plugin-auth-athenz/pkg/config"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/logger"
	"github.com/yahoojapan/athenz-authorizer/policy"
	"github.com/yahoojapan/athenz-authorizer/pubkey"
	"github.com/yahoojapan/athenz-authorizer/role"
)

var (
	updater Athenz
	log     = logger.GetLogger()
)

// Roled updates the policy and public key in the background
type Roled struct {
	domain   []string
	pubkeyd  pubkey.Pubkeydaa
	policyd  policy.Policyd
	rtp      role.RoleTokenParser
	resource string
	action   string
}

// GetUpdater returns the updater instance
func GetUpdater() Athenz {
	return updater
}

// NewAthenzPolicyUpdaterDaemon sets the instance
func NewAthenzPolicyUpdaterDaemon(pluginConfig config.Athenz) error {
	pubkeyd, err := pubkey.NewPubkeyd(
		pubkey.AthenzURL(pluginConfig.URL),
		pubkey.RefreshDuration(pluginConfig.PolicyRefreshDuration),
	)
	if err != nil {
		return err
	}

	policyd, err := policy.NewPolicyd(
		policy.AthenzURL(pluginConfig.URL),
		policy.AthenzDomains(pluginConfig.Domain...),
		policy.PubKeyProvider(pubkeyd.GetProvider()),
	)
	if err != nil {
		return err
	}

	updater = &Updater{
		domain:   pluginConfig.Domain,
		rtp:      role.NewRoleTokenParser(pubkeyd.GetProvider()),
		pubkeyd:  pubkeyd,
		policyd:  policyd,
		resource: pluginConfig.Policy.Resource,
		action:   pluginConfig.Policy.Action,
	}

	return nil
}

func errorWrap(prefix, desc string) string {
	return fmt.Sprintf("%s: %s", prefix, desc)
}

// Run runs the policyd and confd in the background
func (u *Updater) Run(ctx context.Context) {
	cech := u.pubkeyd.StartPubkeyUpdater(ctx)
	pech := u.policyd.StartPolicyUpdater(ctx)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-cech:
				if err != nil {
					log.Debug(errorWrap("update pubkey error", err.Error()))
				}
			case err := <-pech:
				if err != nil {
					log.Debug(errorWrap("update policy error", err.Error()))
				}
			}
		}
	}()
}

// parseRoleToken parses the role token of athenz
func (u *Updater) parseRoleToken(ctx context.Context, t string) (*role.RoleToken, error) {
	rt, err := u.rtp.ParseAndValidateRoleToken(t)
	if err != nil {
		return nil, err
	}
	return rt, nil
}

// VerifyToken verifies the role token with athenz ppolicy
func (u *Updater) VerifyToken(ctx context.Context, t string) (*role.RoleToken, error) {
	// TODO: Convert Ntoken to RoleToken

	rt, err := u.parseRoleToken(ctx, t)
	if err != nil {
		return nil, err
	}

	if err := u.policyd.CheckPolicy(ctx, rt.Domain, rt.Roles, u.action, u.resource); err != nil {
		return nil, err
	}
	return rt, nil
}
