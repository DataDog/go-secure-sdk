# vault

Package vault implements KMS abstraction API to provide Hashicorp Vault support.

## Functions

### func [New](service.go#L43)

`func New(ctx context.Context, client *api.Client, mountPath, keyName string) (kms.Service, error)`

New instantiates a Vault transit backend encryption service.

## Sub Packages

* [logical](./logical): Package logical is a generated GoMock package.

