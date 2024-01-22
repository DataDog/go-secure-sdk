# ff3

Package ff3 provides FF3-1 format preserving encryption primitives.

Credits to [https://github.com/ubiqsecurity/ubiq-fpe-go](https://github.com/ubiqsecurity/ubiq-fpe-go)

## Changes

* FF1 removed due to patent identified for [MicroFocus / Voltage]([https://www.microfocus.com/media/data-sheet/voltage_securedata_security_ds.pdf](https://www.microfocus.com/media/data-sheet/voltage_securedata_security_ds.pdf))
* Support alphabet+based encoding vs fixed radix to support various bases

## Types

### type [FF3_1](ff3_1.go#L31)

`type FF3_1 struct { ... }`

Context structure for the FF3-1 FPE algorithm

#### func [NewFF3_1](ff3_1.go#L44)

`func NewFF3_1(key, twk []byte, alphabet string) (*FF3_1, error)`

Allocate a new FF3-1 context structure

@key specifies the key for the algorithm, the length of which will
determine the underlying aes encryption to use.

@twk specifies the default tweak to be used. the tweak must be
exactly 7 bytes long

@radix species the radix of the input/output data

#### func (*FF3_1) [Decrypt](ff3_1.go#L210)

`func (f *FF3_1) Decrypt(X string, T []byte) (string, error)`

Decrypt a string @X with the tweak @T

@T may be nil, in which case the default tweak will be used

#### func (*FF3_1) [Encrypt](ff3_1.go#L203)

`func (f *FF3_1) Encrypt(X string, T []byte) (string, error)`

Encrypt a string @X with the tweak @T

@T may be nil, in which case the default tweak will be used

