# tlsclient

Package tlsclient provides hardened TLS dialer functions.

## Variables

```golang
var (
    // ErrNoPinMatch is raised when certificate fingerprints doesn't match the
    // given fingerprint.
    ErrNoPinMatch = errors.New("no certificate match the expected fingerprint")

    // ErrCertificateChainTooLong is raised when the certificate chain returned
    // by the TLS handshake is too large.
    ErrCertificateChainTooLong = fmt.Errorf("the certificate chain exceeds the maximum allowed length (%d)", maxCertificateCount)
)
```

## Types

### type [Dialer](secure_dialer.go#L34)

`type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)`

Dialer represents network dialer function for mocking purpose.

#### func [PinnedDialer](secure_dialer.go#L43)

`func PinnedDialer(cfg *tls.Config, fingerPrint []byte) Dialer`

PinnedDialer uses the given tlsconfig configuration to establish an initial
connection with the remote peer, and validate the certificate public key
fingerprint against the given fingerprint.

Use this dialer to ensure a remote peer certificate. This helps to mitigate
DNS based attacks which could be used to reroute/proxy TLS traffic through
an unauthorized peer, and drive the risk to total confidentiality compromise.

```golang

// Get fingerprint from configuration
fgr, err := base64.RawStdEncoding.DecodeString("x6kjj1PTjjAA1BYMa6IzsUjPS7wE+lJ5GFPrfSFc7es")
if err != nil {
    panic(err)
}

// Prepare an HTTP client.
client := httpclient.Safe(
    httpclient.WithTLSDialer(PinnedDialer(
        &tls.Config{InsecureSkipVerify: true},
        fgr,
    )),
)

// Connect to remote server.
_, err = client.Get("https://www.datadoghq.com")
if err != nil {
    panic(err)
}

```

