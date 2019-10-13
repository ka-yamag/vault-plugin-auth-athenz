package athenz

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/katyamag/vault-plugin-auth-athenz/pkg/config"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/testutils"
	"github.com/yahoo/athenz/clients/go/zts"
)

func TestNewValidator(t *testing.T) {
	tests := []struct {
		name        string
		config      config.Athenz
		expectedErr string
	}{
		{
			name: "success",
			config: config.Athenz{
				Domain:                "test.domain",
				URL:                   "https://test.athenz.com",
				PubkeyRefreshDuration: "2m",
				PolicyRefreshDuration: "2m",
				Policy: config.Policy{
					Resource: "vault",
					Action:   "access",
				},
			},
		},
		{
			name: "failed to url parse",
			config: config.Athenz{
				Domain:                "test.domain",
				URL:                   "http://[fe80::1%en0]",
				PubkeyRefreshDuration: "2m",
				PolicyRefreshDuration: "2m",
				Policy: config.Policy{
					Resource: "vault",
					Action:   "access",
				},
			},
			expectedErr: `parse http://[fe80::1%en0]: invalid URL escape "%en"`,
		},
		{
			name: "invalid athenz domain",
			config: config.Athenz{
				Domain:                "+-invalid.test.domain",
				URL:                   "http://test.athenz.com",
				PubkeyRefreshDuration: "2m",
				PolicyRefreshDuration: "2m",
				Policy: config.Policy{
					Resource: "vault",
					Action:   "access",
				},
			},
			expectedErr: "Invalid athenz domain",
		},
		{
			name: "failed to create pubkeyd when the pubkeyRefreshDuration is invalid",
			config: config.Athenz{
				Domain:                "test.domain.com",
				URL:                   "http://test.athenz.com",
				PubkeyRefreshDuration: "invalid duration",
				PolicyRefreshDuration: "2m",
				Policy: config.Policy{
					Resource: "vault",
					Action:   "access",
				},
			},
			expectedErr: "error create pubkeyd: invalid refresh duration: time: invalid duration invalid duration",
		},
		{
			name: "failed to create pubkeyd when the policyRefreshDuration is invalid",
			config: config.Athenz{
				Domain:                "test.domain.com",
				URL:                   "http://test.athenz.com",
				PubkeyRefreshDuration: "1h",
				PolicyRefreshDuration: "invalid duration",
				Policy: config.Policy{
					Resource: "vault",
					Action:   "access",
				},
			},
			expectedErr: "error create policyd: error create policyd: invalid refresh duration: time: invalid duration invalid duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := NewValidator(tt.config)
			if actual != nil && actual.Error() != tt.expectedErr {
				t.Errorf("NewValidator() actual = %v, expected = %v", actual, tt.expectedErr)
				return
			}
		})
	}
}

func Test_validator_Init(t *testing.T) {
	tests := []struct {
		name        string
		authorizerd *MockAuthorizerd
		expectedErr string
	}{
		{
			name:        "success",
			authorizerd: &MockAuthorizerd{},
		},
		{
			name: "failed to init",
			authorizerd: &MockAuthorizerd{
				initErr: errors.New("initialize authorizerd error"),
			},
			expectedErr: "initialize authorizerd error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Validator{
				authorizerDaemon: tt.authorizerd,
			}
			err := v.Init(context.Background())
			if err != nil && err.Error() != tt.expectedErr {
				t.Errorf("Init() actual = %v, expected = %v", err, tt.expectedErr)
				return
			}
		})
	}
}

func Test_validator_Start(t *testing.T) {
	type test struct {
		name        string
		expectedErr string
		checkFunc   func() error
	}

	tests := []test{
		func() test {
			ctx, cancel := context.WithCancel(context.Background())
			v := Validator{
				authorizerDaemon: &MockAuthorizerd{},
			}

			return test{
				name: "success",
				checkFunc: func() error {
					v.Start(ctx)

					time.Sleep(time.Millisecond * 100)

					cancel()

					return nil
				},
			}
		}(),
		// TODO: check logs
		func() test {
			ctx, cancel := context.WithCancel(context.Background())
			v := Validator{
				authorizerDaemon: &MockAuthorizerd{
					startErr: "error",
				},
			}

			return test{
				name: "failure",
				checkFunc: func() error {
					v.Start(ctx)

					time.Sleep(time.Millisecond * 100)

					cancel()

					return nil
				},
			}
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.checkFunc()
			if err != nil {
				t.Errorf("Start() actual = %v, expected = %v", err, tt.expectedErr)
				return
			}
		})
	}
}

func Test_validator_VerifyToken(t *testing.T) {
	type args struct {
		ctx    context.Context
		url    string
		ntoken string
		role   string
	}

	type mocks struct {
		tr          *testutils.MockTransporter
		authorizerd *MockAuthorizerd
	}

	type expects struct {
		errStr    string
		roleToken *zts.RoleToken
	}

	url, _ := url.Parse("https://test.athenz.com")

	tests := []struct {
		name    string
		args    args
		mocks   mocks
		expects expects
	}{
		{
			name: "success",
			args: args{
				url:    url.String(),
				ctx:    context.Background(),
				ntoken: "test_ntoken",
				role:   "access_role",
			},
			mocks: mocks{
				tr: &testutils.MockTransporter{
					StatusCode: 200,
					Method:     "GET",
					Body:       []byte(`{"token": "test_roletoken"}`),
					URL:        url,
				},
				authorizerd: &MockAuthorizerd{},
			},
			expects: expects{
				roleToken: &zts.RoleToken{
					Token: "test_roletoken",
				},
			},
		},
		{
			name: "failed to get roletoken when the domain does not exists",
			args: args{
				url:    url.String(),
				ctx:    context.Background(),
				ntoken: "test_ntoken",
				role:   "access_role",
			},
			mocks: mocks{
				tr: &testutils.MockTransporter{
					StatusCode: 404,
					Method:     "GET",
					Body:       []byte(`{"code": 404, "message": "domain is not found"}`),
					URL:        url,
				},
				authorizerd: &MockAuthorizerd{},
			},
			expects: expects{
				errStr: "404 domain is not found",
			},
		},
		{
			name: "failed to get roletoken when it sends the request to unauthorized domain",
			args: args{
				url:    url.String(),
				ctx:    context.Background(),
				ntoken: "test_ntoken",
				role:   "access_role",
			},
			mocks: mocks{
				tr: &testutils.MockTransporter{
					StatusCode: 403,
					Method:     "GET",
					Body:       []byte(`{"code": 403, "message": "Forbidden"}`),
					URL:        url,
				},
				authorizerd: &MockAuthorizerd{},
			},
			expects: expects{
				errStr: "403 Forbidden",
			},
		},
		{
			name: "failed to verify roletoken",
			args: args{
				url:    url.String(),
				ctx:    context.Background(),
				ntoken: "test_ntoken",
				role:   "access_role",
			},
			mocks: mocks{
				tr: &testutils.MockTransporter{
					StatusCode: 200,
					Method:     "GET",
					Body:       []byte(`{"token": "invalid_roletoken"}`),
					URL:        url,
				},
				authorizerd: &MockAuthorizerd{
					verifyRoleTokenErr: errors.New("invalid roletoken"),
				},
			},
			expects: expects{
				errStr: "invalid roletoken",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Validator{
				authorizerDaemon: tt.mocks.authorizerd,
				client:           zts.NewClient(tt.args.url, tt.mocks.tr),
			}

			roleToken, err := v.VerifyToken(tt.args.ctx, tt.args.ntoken, tt.args.role)
			if err != nil && err.Error() != tt.expects.errStr {
				t.Errorf("VerifyToken(): err actual = %v, expected = %v", err.Error(), tt.expects.errStr)
				return
			}
			if tt.expects.roleToken != nil && !reflect.DeepEqual(roleToken, tt.expects.roleToken) {
				t.Errorf("VerifyToken(): roleToken actual = %v, expected = %v", roleToken, tt.expects.roleToken)
				return
			}
		})
	}
}
