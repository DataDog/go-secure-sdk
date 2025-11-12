# Go Secure SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/DataDog/go-secure-sdk.svg)](https://pkg.go.dev/github.com/DataDog/go-secure-sdk)
[![Go Report Card](https://goreportcard.com/badge/github.com/DataDog/go-secure-sdk)](https://goreportcard.com/report/github.com/DataDog/go-secure-sdk)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A comprehensive security-focused Go SDK providing secure-by-default implementations for common operations that are prone to security vulnerabilities. This project is designed to be a one-stop-shop for security features and libraries for Go developers.

## Overview

The Go Secure SDK is part of Datadog's commitment to secure software development. It provides a set of libraries to mitigate common security issues and vulnerabilities across various domains including compression, cryptography, I/O operations, networking, and filesystem operations.

## Features

- **🔒 Secure by Default**: All components implement security best practices out of the box
- **🛡️ Attack Prevention**: Built-in protection against common attacks (zip-slip, SSRF, path traversal, etc.)
- **⚡ Production Ready**: Battle-tested code used in Datadog's production environments
- **📦 Modular Design**: Use only the packages you need
- **🧪 Well Tested**: Comprehensive test coverage with security-focused test cases
- **📚 Well Documented**: Extensive documentation and examples for every package

## Installation

```bash
go get github.com/DataDog/go-secure-sdk
```

## Requirements

- Go 1.24.0 or higher

## Packages

### 🗜️ Compression & Archives

#### `compression/archive/tar`

Secure TAR archive creation and extraction with protection against:
- Zip-slip attacks
- Path traversal attacks
- Archive bombs (size/count limits)
- Symbolic link recursion attacks

```go
import "github.com/DataDog/go-secure-sdk/compression/archive/tar"

// Extract with security controls
err := tar.Extract(reader, "/safe/output/path",
    tar.WithMaxArchiveSize(100 << 20),  // 100MB max
    tar.WithMaxEntryCount(10000),       // Max 10k files
    tar.WithMaxFileSize(10 << 20),      // 10MB per file
)
```

[📖 Documentation](compression/archive/tar/README.md)

#### `compression/archive/zip`

Hardened ZIP archive operations with similar security controls as TAR.

```go
import "github.com/DataDog/go-secure-sdk/compression/archive/zip"

// Create with compression control
err := zip.Create(fileSystem, writer,
    zip.WithCompressionLevel(flate.DefaultCompression),
    zip.WithExcludeFilter(func(path string, fi fs.FileInfo) bool {
        return strings.HasSuffix(path, ".zip")
    }),
)
```

[📖 Documentation](compression/archive/zip/README.md)

### 🔐 Cryptography

#### `crypto/hashutil`

Secure cryptographic hash functions with support for multiple algorithms in a single pass.

```go
import "github.com/DataDog/go-secure-sdk/crypto/hashutil"

// Compute multiple hashes in one read
hashes, err := hashutil.FileHashes(root, "file.bin",
    crypto.SHA256,
    crypto.SHA384,
    crypto.SHA512,
)
```

[📖 Documentation](crypto/hashutil/README.md)

#### `crypto/keyutil`

Comprehensive cryptographic key management supporting multiple formats and operations.

```go
import "github.com/DataDog/go-secure-sdk/crypto/keyutil"

// Generate key pair
pub, priv, err := keyutil.GenerateKeyPair(keyutil.EC)

// Convert to JWK
jwk, err := keyutil.ToJWK(priv)

// Encrypt JWK with password
encrypted, err := keyutil.ToEncryptedJWK(jwk, []byte("password"))
```

[📖 Documentation](crypto/keyutil/README.md)

### 🎲 Random Generation

#### `generator/randomness`

Cryptographically secure random generation with `math/rand` compatible API.

```go
import "github.com/DataDog/go-secure-sdk/generator/randomness"

// Drop-in replacement for math/rand with crypto/rand backing
randomNumber := randomness.Intn(100)

// Generate secure tokens
token, err := randomness.Alphanumeric(32)
verificationCode, err := randomness.VerificationCode(6)
```

[📖 Documentation](generator/randomness/README.md)

### 💾 I/O Operations

#### `ioutil`

Hardened I/O operations with size limits and timeouts.

```go
import "github.com/DataDog/go-secure-sdk/ioutil"

// Copy with size limit (prevents decompression bombs)
size, err := ioutil.LimitCopy(dst, src, 10 << 20)  // Max 10MB

// Reader with timeout protection
timeoutReader := ioutil.TimeoutReader(slowReader, 5*time.Second)
```

[📖 Documentation](ioutil/README.md)

### 🌐 Networking

#### `net/httpclient`

SSRF-safe HTTP client implementation with request/response filtering.

```go
import "github.com/DataDog/go-secure-sdk/net/httpclient"

// Safe client blocks dangerous requests
client := httpclient.Safe()

// This will be blocked (metadata service)
resp, err := client.Get("http://169.254.169.254/")
// Error: address is link local unicast

// Customize with options
client = httpclient.Safe(
    httpclient.WithTimeout(30*time.Second),
    httpclient.WithFollowRedirect(true),
)
```

[📖 Documentation](net/httpclient/README.md)

#### `net/tlsclient`

TLS dialer with certificate pinning support.

```go
import "github.com/DataDog/go-secure-sdk/net/tlsclient"

// Pin to specific certificate fingerprint
dialer := tlsclient.PinnedDialer(tlsConfig, fingerprint)

client := httpclient.Safe(
    httpclient.WithTLSDialer(dialer),
)
```

[📖 Documentation](net/tlsclient/README.md)

### 📁 Filesystem

#### `vfs`

Virtual filesystem with security constraints preventing path traversal.

```go
import "github.com/DataDog/go-secure-sdk/vfs"

// Create chrooted filesystem
fs, err := vfs.Chroot("/safe/base/path")

// Path traversal attempts are blocked
err = fs.Mkdir("../../../etc", 0755)
// Returns: ConstraintError

// Confirmed directories
tmpDir, err := vfs.NewTmpConfirmedDir()
safePath := tmpDir.Join("subdir/file.txt")
```

[📖 Documentation](vfs/README.md)

## Security Best Practices

This SDK is designed to help you follow security best practices:

1. **Input Validation**: Always validate and sanitize user inputs before processing
2. **Size Limits**: Use the built-in size limits to prevent resource exhaustion
3. **Timeouts**: Apply reasonable timeouts to prevent hanging operations
4. **Least Privilege**: Use chrooted filesystems and network restrictions
5. **Defense in Depth**: Combine multiple security layers

## Common Use Cases

### Secure Archive Extraction

```go
// Extract user-uploaded archive safely
func extractUpload(uploadPath, destPath string) error {
    f, err := os.Open(uploadPath)
    if err != nil {
        return err
    }
    defer f.Close()

    // Create chrooted extraction directory
    fs, err := vfs.Chroot(destPath)
    if err != nil {
        return err
    }

    // Extract with all safety checks
    return tar.Extract(
        io.LimitReader(f, 100<<20), // Max 100MB
        fs.Root(),
        tar.WithMaxEntryCount(1000),
        tar.WithMaxFileSize(10<<20),
    )
}
```

### SSRF-Safe HTTP Requests

```go
// Fetch URL from user input safely
func fetchURL(userURL string) ([]byte, error) {
    client := httpclient.Safe(
        httpclient.WithTimeout(10*time.Second),
    )

    resp, err := client.Get(userURL)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // Read with size limit
    return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
```

### Secure File Hashing

```go
// Verify file integrity with multiple algorithms
func verifyFile(path string, expected map[crypto.Hash]string) error {
    root := os.DirFS(filepath.Dir(path))
    name := filepath.Base(path)

    hashes, err := hashutil.FileHashes(root, name,
        crypto.SHA256,
        crypto.SHA512,
    )
    if err != nil {
        return err
    }

    for algo, hash := range hashes {
        if hex.EncodeToString(hash) != expected[algo] {
            return fmt.Errorf("hash mismatch for %s", algo)
        }
    }
    return nil
}
```

## Testing

Run the test suite:

```bash
go test ./...
```

Run tests with race detection:

```bash
go test -race ./...
```

Run tests with coverage:

```bash
go test -cover ./...
```

## Contributing

We welcome contributions! Please see our contributing guidelines for more details.

Before submitting a pull request:

1. Ensure all tests pass
2. Add tests for new functionality
3. Update documentation as needed
4. Follow the existing code style
5. Write clear commit messages

## Security

Security is our top priority. If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md).

**Please DO NOT file a public issue. Instead, send your report privately to security@datadoghq.com**

We greatly appreciate security reports and will publicly thank you for it (with your permission).

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

Copyright 2024-present Datadog, Inc.

## Acknowledgments

This SDK is developed and maintained by Datadog to support our open-source projects and is made available to the broader Go community.

## Related Projects

- [DataDog/datadog-agent](https://github.com/DataDog/datadog-agent) - Datadog Agent
- [DataDog/go-libddwaf](https://github.com/DataDog/go-libddwaf) - Go bindings for libddwaf

## Support

- 📖 [Documentation](https://pkg.go.dev/github.com/DataDog/go-secure-sdk)
- 🐛 [Issue Tracker](https://github.com/DataDog/go-secure-sdk/issues)
- 💬 [Discussions](https://github.com/DataDog/go-secure-sdk/discussions)

---

**Built with ❤️ by Datadog**

