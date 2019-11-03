package athenz

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"github.com/katyamag/vault-plugin-auth-athenz/pkg/config"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/logger"
	"github.com/yahoo/athenz/clients/go/zts"
	authorizerd "github.com/yahoojapan/athenz-authorizer/v2"
)

const defaultHdr = "Yahoo-Principal-Auth"

var (
	validator        Athenz
	log              = logger.GetLogger()
	domainReg        = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_-]*\.)*[a-zA-Z_][a-zA-Z0-9_-]*$`)
	errInvalidDomain = errors.New("Invalid athenz domain")
)

// Validator updates the policy and public key in the background
type Validator struct {
	domain           string
	authorizerDaemon authorizerd.Authorizerd
	resource         string
	action           string
	client           zts.ZTSClient
	hdr              string
}

// GetValidator returns the updater instance
func GetValidator() Athenz {
	return validator
}

// NewValidator sets the instance
func NewValidator(pluginConfig config.Athenz) error {
	url, err := url.Parse(pluginConfig.URL)
	if err != nil {
		return err
	}

	if !domainReg.MatchString(pluginConfig.Domain) {
		return errInvalidDomain
	}

	if validator != nil {
		return nil
	}

	daemon, err := authorizerd.New(
		authorizerd.WithAthenzURL(url.String()),
		authorizerd.WithAthenzDomains(pluginConfig.Domain),
		authorizerd.WithPubkeyRefreshDuration(pluginConfig.PubkeyRefreshDuration),
		authorizerd.WithPolicyRefreshDuration(pluginConfig.PolicyRefreshDuration),
		authorizerd.WithDisableJwkd(),
	)
	if err != nil {
		return err
	}

	hdr := pluginConfig.Hdr
	if hdr == "" {
		hdr = defaultHdr
	}

	log.Debug(url.String())

	validator = &Validator{
		domain:           pluginConfig.Domain,
		authorizerDaemon: daemon,
		resource:         pluginConfig.Policy.Resource,
		action:           pluginConfig.Policy.Action,
		client:           zts.NewClient(url.String(), nil),
		hdr:              hdr,
	}

	return nil
}

func errorWrap(prefix, desc string) string {
	return fmt.Sprintf("%s: %s", prefix, desc)
}

// Init is initialization and starting daemon
func (v *Validator) Init(ctx context.Context) error {
	return v.authorizerDaemon.Init(ctx)
}

// Start runs the policyd and confd in the background
func (v *Validator) Start(ctx context.Context) {
	errs := v.authorizerDaemon.Start(ctx)
	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Debug("halt daemon")
				return
			case err := <-errs:
				if err != nil {
					log.Error(errorWrap("daemon error", err.Error()))
				}
			}
		}
	}()
}

// VerifyToken verifies the role token with athenz ppolicy
func (v *Validator) VerifyToken(ctx context.Context, ntoken, role string) (*zts.RoleToken, error) {
	v.client.AddCredentials(v.hdr, ntoken)

	// zts timeout is in seconds so we'll convert our value
	expireTimeMs := int32(60)

	// request a roletoken
	roleToken, err := v.client.GetRoleToken(zts.DomainName(v.domain), zts.EntityList(role), &expireTimeMs, &expireTimeMs, "")
	if err != nil {
		return nil, err
	}

	if err := v.authorizerDaemon.VerifyRoleToken(ctx, roleToken.Token, v.action, v.resource); err != nil {
		return nil, err
	}

	return roleToken, nil
}
