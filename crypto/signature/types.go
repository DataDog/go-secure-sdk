package signature

type Algorithm string

const (
	UnknownSignature   Algorithm = "unknown"
	Ed25519Signature   Algorithm = "ed25519"
	ECDSAP256Signature Algorithm = "ecdsa-p256"
	ECDSAP384Signature Algorithm = "ecdsa-p384"
	ECDSAP521Signature Algorithm = "ecdsa-p521"
)
