package hasher

// Algorithm is the password hashing strategy code
type Algorithm uint8

const (
	// Argon2id defines the argon2id hashing algorithm
	Argon2id = Algorithm(0x01)
	// Pbkdf2HmacSha512 defines pbkdf2+hmac-sha512 hashing algorithm
	Pbkdf2HmacSha512 = Algorithm(0x02)
)

const (
	kdfOutputLen = 64
)

// Strategy defines hash algorithm strategy contract
type Strategy interface {
	Hash([]byte) (*Metadata, error)
}
