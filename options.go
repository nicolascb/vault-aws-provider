package provider

import (
	"errors"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// Option represents the options to initialize provider
type Option func(*Provider) error

// WithAuthBeforeRetrieve enable authentication before retrieving secrets
// Should be used in cases where it is necessary to renew authentication
// to the vault
func WithAuthBeforeRetrieve() Option {
	return func(p *Provider) error {
		p.config.authBeforeRetrieve = true
		return nil
	}
}

// WithCredentialsParser parser for vault.Secret to aws.Credentials
// It is used as a callback after fetching secrets from vault
func WithCredentialsParser(parser CredentialsParser) Option {
	return func(p *Provider) error {
		if parser == nil {
			return errors.New("parser can't be nil")
		}

		p.config.parser = parser
		return nil
	}
}

// WithCustomVaultConfig use a custom config for vault
func WithCustomVaultConfig(c *vault.Config) Option {
	return func(p *Provider) error {
		if c == nil {
			return errors.New("custom config can't be nil")
		}

		p.config.vaultConfig = c
		return nil
	}
}

// WithVaultToken add a vault token
func WithVaultToken(token string) Option {
	return func(p *Provider) error {
		if token == "" {
			return errors.New("token can't be empty")
		}

		p.config.token = strings.TrimSpace(token)
		return nil
	}
}

// WithAuthMethod use vault.AuthMethod to authenticate
// If you need to renew authentication, you should use WithAuthBeforeRetrieve
func WithAuthMethod(auth vault.AuthMethod) Option {
	return func(p *Provider) error {
		if auth == nil {
			return errors.New("vault.AuthMethod can't be nil")
		}

		p.config.authMethod = auth
		return nil
	}
}
