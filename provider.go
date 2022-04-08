package provider

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	vault "github.com/hashicorp/vault/api"
)

// tNow represents the time.Now
// this way we can use it in the tests
var tNow = time.Now

// CredentialsParser represent a parser for aws credentials
type CredentialsParser func(*vault.Secret) (aws.Credentials, error)

type providerConfig struct {
	// secretPath represents the credentials path
	secretPath string

	// token represents the vault token
	token string

	// authBeforeRetrieve if true it will call vault.AuthMethod in the
	// Retrieve method
	authBeforeRetrieve bool

	// parser if different from nil it is used as a callback after fetching
	// secrets from vault
	parser CredentialsParser

	// authMethod represents the vault authentication method
	authMethod vault.AuthMethod

	// vaultConfig represents the vault config
	vaultConfig *vault.Config
}

// Provider implements aws.CredentialsProvider
type Provider struct {
	// config
	config providerConfig

	// logical represents the vault.Logical
	logical Logicaler

	// auth represents the vault.Auth
	auth Auth
}

// NewProvider initialize vault provider
func NewProvider(ctx context.Context, secretPath string, opts ...Option) (*Provider, error) {
	p := &Provider{
		config: providerConfig{
			secretPath: secretPath,
		},
	}

	for _, option := range opts {
		if err := option(p); err != nil {
			return nil, err
		}
	}

	if p.config.vaultConfig == nil {
		p.config.vaultConfig = vault.DefaultConfig()
	}

	c, err := vault.NewClient(p.config.vaultConfig)
	if err != nil {
		return nil, err
	}

	if p.config.token != "" {
		c.SetToken(p.config.token)
	}

	if p.config.authMethod != nil {
		if _, err := c.Auth().Login(ctx, p.config.authMethod); err != nil {
			return nil, err
		}
	}

	p.logical = c.Logical()
	p.auth = c.Auth()

	return p, nil
}

// Retrieve aws credentials
func (p *Provider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if p.config.authBeforeRetrieve {
		if _, err := p.auth.Login(ctx, p.config.authMethod); err != nil {
			return aws.Credentials{}, err
		}
	}

	res, err := p.logical.Read(p.config.secretPath)
	if err != nil {
		return aws.Credentials{}, err
	}

	if p.config.parser != nil {
		return p.config.parser(res)
	}

	return toAWSCredentials(res)
}

func toAWSCredentials(res *vault.Secret) (aws.Credentials, error) {
	ttl, err := res.TokenTTL()
	if err != nil {
		return aws.Credentials{}, err
	}

	secretKey, ok := res.Data["secret_key"]
	if !ok {
		return aws.Credentials{}, errors.New("secret_key not found")
	}

	accessKey, ok := res.Data["access_key"]
	if !ok {
		return aws.Credentials{}, errors.New("access_key not found")
	}

	token, ok := res.Data["security_token"]
	if !ok {
		return aws.Credentials{}, errors.New("security_token not found")
	}

	creds := aws.Credentials{
		AccessKeyID:     accessKey.(string),
		SecretAccessKey: secretKey.(string),
		SessionToken:    token.(string),
	}

	canExpire := (ttl > 0)
	if canExpire {
		creds.CanExpire = true
		creds.Expires = tNow().Add(ttl)
	}

	return creds, nil
}
