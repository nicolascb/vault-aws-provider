# vault-aws-provider [![GoDoc](https://img.shields.io/badge/pkg.go.dev-doc-blue)](https://pkg.go.dev/github.com/nicolascb/vault-aws-provider)

`vault-aws-provider` is an implementation for [AWS Credentials Provider](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2@v1.16.2/aws#CredentialsProvider) using Vault to fetch credentials.

## Features

-  Custom auth methods via [vault.AuthMethod](https://pkg.go.dev/github.com/hashicorp/vault/api#AuthMethod)  
- Callback on retrieve
- Token authentication
- Renew token when retrieving credentials

## Usage

```go
import (
	...
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	vaultp "github.com/nicolascb/vault-aws-provider"
)

...
endpoint := "aws/sts/my-secret"
token := "my_vault_auth_token"
provider, err := vaultp.NewProvider(context.TODO(), endpoint, vaultp.WithVaultToken(token))
...

// can now use when initializing config
c, err := awscfg.LoadDefaultConfig(context.TODO(), awscfg.WithCredentialsProvider(provider))
...
```

## Custom auth methods

You can use any authentication method that implements [vault.AuthMethod](https://pkg.go.dev/github.com/hashicorp/vault/api#AuthMethod) , such as the methods provided by the [vault sdk](https://github.com/hashicorp/vault/tree/api/v1.5.0/api/auth).

Authentication example with Kubernetes:

```go
import (
	...
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	vaultp "github.com/nicolascb/vault-aws-provider"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
)

func main() {
	endpoint := "aws/sts/my-secret"
	kubeAuth, err := auth.NewKubernetesAuth(
		role,
		auth.WithServiceAccountTokenPath(tokenPath),
	)

	// initialize provider
	provider, err := vaultp.NewProvider(
		context.TODO(),
		endpoint,
		vaultp.WithAuthMethod(kubeAuth),
		// for renew on retrieve
		vaultp.WithAuthBeforeRetrieve())

	// can now use when initializing config
	c, err := awscfg.LoadDefaultConfig(context.TODO(), awscfg.WithCredentialsProvider(provider))
```

## License

Released under the  [Apache License 2.0](https://github.com/nicolascb/vault-aws-provider/blob/main/LICENSE).
