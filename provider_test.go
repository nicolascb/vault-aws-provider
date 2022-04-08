package provider

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/golang/mock/gomock"
	vault "github.com/hashicorp/vault/api"
	mock_provider "github.com/nicolascb/vault-aws-provider/mocks"
	"github.com/stretchr/testify/assert"
)

type fakeAuthMethod struct {
	token string
}

func (fa *fakeAuthMethod) Login(ctx context.Context, c *vault.Client) (*vault.Secret, error) {
	return &vault.Secret{
		Auth: &vault.SecretAuth{
			ClientToken: fa.token,
		},
	}, nil
}

func TestNewProviderDefaults(t *testing.T) {
	const secretPath = "test/secret/path"
	assert := assert.New(t)
	p, err := NewProvider(context.TODO(), secretPath)
	assert.Nil(err)
	assert.Equal(p.config.authBeforeRetrieve, false, "expected true for authBeforeRetrieve")
	assert.Equal(p.config.secretPath, secretPath, "secretPath is different")
	assert.Nil(p.config.parser)
	assert.Nil(p.config.authMethod)

	if assert.NotNil(p.config.vaultConfig) {
		assert.Equal(p.config.vaultConfig.Address, vault.DefaultConfig().Address, "expected default address in vaultConfig")
	}
}

func TestNewProviderWithOptions(t *testing.T) {
	const secretPath = "test/secret/path"
	assert := assert.New(t)
	authMethod := &fakeAuthMethod{token: "fakeToken"}
	parser := func(s *vault.Secret) (aws.Credentials, error) {
		return aws.Credentials{}, nil
	}

	cfg := vault.DefaultConfig()
	cfg.Address = "http://mycustom.endpoint/"
	p, err := NewProvider(context.TODO(), secretPath,
		WithAuthBeforeRetrieve(),
		WithCustomVaultConfig(cfg),
		WithCredentialsParser(parser),
		WithVaultToken("token"),
		WithAuthMethod(authMethod),
	)
	assert.Nil(err)
	assert.Equal(p.config.token, "token", "expected token in config")
	assert.Equal(p.config.authBeforeRetrieve, true, "expected true for authBeforeRetrieve")
	assert.Equal(p.config.secretPath, secretPath, "secretPath is different")
	assert.NotNil(p.config.parser)
	assert.NotNil(p.config.authMethod)

	if assert.NotNil(p.config.vaultConfig) {
		assert.Equal(p.config.vaultConfig.Address, cfg.Address, "expected replace vaultConfig")
	}
}

// TODO: add error cases
func TestProviderRetrieve(t *testing.T) {
	const secretPath = "test/secret/path"
	fakeNow, _ := time.Parse("2006-Jan-02", "2022-Abr-28")
	tNow = func() time.Time {
		return fakeNow
	}

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	secret := &vault.Secret{
		Data: map[string]interface{}{
			"secret_key":     "test_secret",
			"access_key":     "test_access",
			"security_token": "test_token",
		},
	}
	creds := aws.Credentials{
		AccessKeyID:     "test_access",
		SecretAccessKey: "test_secret",
		SessionToken:    "test_token",
	}

	type fields struct {
		config  providerConfig
		logical func() Logicaler
		auth    func() Auth
	}
	tests := []struct {
		name    string
		fields  fields
		want    func() aws.Credentials
		wantErr bool
	}{
		{
			name: "success case with authBeforeLogin = true",
			fields: fields{
				config: providerConfig{
					secretPath:         secretPath,
					authBeforeRetrieve: true,
					authMethod:         &fakeAuthMethod{token: "fakeToken"},
				},
				logical: func() Logicaler {
					logicaler := mock_provider.NewMockLogicaler(mockCtrl)
					logicaler.EXPECT().Read(secretPath).Return(secret, nil)
					return logicaler
				},
				auth: func() Auth {
					authmock := mock_provider.NewMockAuth(mockCtrl)
					authmock.EXPECT().Login(gomock.Any(), gomock.Any()).Return(nil, nil)
					return authmock
				},
			},
			want: func() aws.Credentials {
				return creds
			},
			wantErr: false,
		},
		{
			name: "success case with default values",
			fields: fields{
				config: providerConfig{
					secretPath: secretPath,
				},
				logical: func() Logicaler {
					logicaler := mock_provider.NewMockLogicaler(mockCtrl)
					logicaler.EXPECT().Read(secretPath).Return(secret, nil)
					return logicaler
				},
				auth: func() Auth {
					return nil
				},
			},
			want: func() aws.Credentials {
				return creds
			},
			wantErr: false,
		},
		{
			name: "success case with ttl",
			fields: fields{
				config: providerConfig{
					secretPath: secretPath,
				},
				logical: func() Logicaler {
					s := *secret
					s.Data["ttl"] = "60m"
					logicaler := mock_provider.NewMockLogicaler(mockCtrl)
					logicaler.EXPECT().Read(secretPath).Return(&s, nil)
					return logicaler
				},
				auth: func() Auth {
					return nil
				},
			},
			want: func() aws.Credentials {
				credsExpire := creds
				credsExpire.CanExpire = true
				credsExpire.Expires = fakeNow.Add(60 * time.Minute)
				return credsExpire
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{
				config:  tt.fields.config,
				logical: tt.fields.logical(),
				auth:    tt.fields.auth(),
			}
			got, err := p.Retrieve(context.TODO())
			if (err != nil) != tt.wantErr {
				t.Errorf("Provider.Retrieve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want()) {
				t.Errorf("Provider.Retrieve() = %v, want %v", got, tt.want())
			}
		})
	}
}
