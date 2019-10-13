package athenz

import (
	"fmt"
	"testing"

	"github.com/katyamag/vault-plugin-auth-athenz/pkg/config"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/testutils"
)

func TestNewValidator(t *testing.T) {
	cases := []struct {
		config config.Athenz
		tr     testutils.MockTransporter
	}{
		{
			config: config.Athenz{},
			tr: testutils.MockTransporter{
				StatusCode: 200,
				Method:     "GET",
			},
		},
	}

	for _, c := range cases {
		// ctx, cancel := context.WithCancel(context.Background())
		// defer cancel()

		// NewValidator(ctx, c.config, c.tr)
		fmt.Printf("c = %+v\n", c)
	}
}

func TestValidator_Start(t *testing.T) {
	cases := []struct {
		mockAuthorizerd MockAuthorizerd
	}{
		{
			mockAuthorizerd: MockAuthorizerd{
				startErr: "dummy error",
			},
		},
	}

	t.Run("start update routine successfully", func(t *testing.T) {

	})
}
