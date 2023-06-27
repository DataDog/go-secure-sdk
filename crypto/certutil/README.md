# certutil

Package certutil provides X.509 Certificate related functions.

## Functions

### func [Fingerprint](fingerprint.go#L21)

`func Fingerprint(cert *x509.Certificate) ([]byte, error)`

Fingerprint generates a certificate fingerprint from the given
certificate instance.
[https://www.rfc-editor.org/rfc/rfc7515#section-4.1.8](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.8)

The certificate fingerprint can be used to ensure a known server reached by
TLS communication. The downside of this, is that the finger print will change
after each certificate changes.
To be resilient, it is recommended to use the public key fingerprint as a
reference from `keyutil.Fingerprint()`.

```golang
// Decode certificate
b, _ := pem.Decode(serverCertPEM)
cert, err := x509.ParseCertificate(b.Bytes)
if err != nil {
    panic(err)
}

out, err := Fingerprint(cert)
if err != nil {
    panic(err)
}
```

 Output:

```
13f013ba27522762e76a7421a2089c407a476cef8750f8a231fa736e9bb4bf55
```

