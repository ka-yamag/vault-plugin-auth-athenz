package athenz

import (
	"context"
	"net/http"
	"testing"

	"github.com/katyamag/vault-plugin-auth-athenz/pkg/config"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/testutils"
	"github.com/stretchr/testify/assert"
)

func TestNewValidator(t *testing.T) {
	cases := []struct {
		config config.Athenz
		// tr       *http.Transport
		tr       *testutils.MockTransporter
		expected error
	}{
		{
			config: config.Athenz{
				URL:                   "www.athenz.com",
				PolicyRefreshDuration: "10m",
				Domain:                "test.domain",
				Policy: config.Policy{
					Resource: "vault",
					Action:   "access",
				},
			},
			tr: &testutils.MockTransporter{
				StatusCode: http.StatusOK,
			},
			expected: nil,
		},
	}

	for _, c := range cases {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		tr := &http.Transport{}
		result := NewValidator(ctx, c.config, tr)
		assert.Equal(t, c.expected, result)
	}
}

// func TestVerifyToken(t *testing.T) {
//   t.Run("verify successfully", func(t *testing.T) {

//   })
// }

// func testVerifyToken(t *testing.T, authorizedrDaemon authorizerd.Authorizerd) {
// }
