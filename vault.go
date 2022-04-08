//go:generate mockgen -destination=mocks/${GOFILE} -source=$GOFILE .
package provider

import (
	"context"

	vault "github.com/hashicorp/vault/api"
)

// Logicaler interface represents the vault.Logical().Read method
type Logicaler interface {
	Read(path string) (*vault.Secret, error)
}

// Auth interface represents the vault.Auth().Login method
type Auth interface {
	Login(context.Context, vault.AuthMethod) (*vault.Secret, error)
}

type vaultClient struct {
	logical Logicaler
	auth    Auth
}
