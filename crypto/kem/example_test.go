package kem

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/DataDog/go-secure-sdk/crypto/canonicalization"
	"github.com/DataDog/go-secure-sdk/crypto/encryption"

	"golang.org/x/crypto/hkdf"
)

func ExampleScheme_Encapsulate() {
	// We want to send a message to a receiver which will be the only one able to
	// read the message.
	receiverPublicKeyRaw, _ := hex.DecodeString("04d356f8ab8351ac9e9268979c7afde9e539c4609e00e95ec60cb5d4df36937049f2e4e4be6c06f9bf66afcebcabfa63bb53969abaa5e25d659c7986e3fd35a757")

	// Key agreement exchange algorithm to use. This is a configuration element.
	suite := DHP256HKDFSHA256()
	receiverPublicKey, err := suite.DeserializePublicKey(receiverPublicKeyRaw)
	if err != nil {
		panic(err)
	}

	// Prepare an ephemeral encryption key
	sharedSecret, encapsulationPublicKey, err := suite.Encapsulate(receiverPublicKey)
	if err != nil {
		panic(err)
	}

	// Split the shared secret to extract an encryption key.
	var (
		keyLen    = uint16(32)
		keyLenRaw [2]byte
	)

	// Encode the key length as byte.
	binary.BigEndian.PutUint16(keyLenRaw[:], keyLen)

	// Prepare key split information. It is used to explain why you are
	// splitting a secret.
	info, err := canonicalization.PreAuthenticationEncoding(
		[]byte("unidirectional_message_encryption_key"), // Why
		suite.SuiteID(),      // How
		receiverPublicKeyRaw, // Who
		keyLenRaw[:],         // Key size
	)
	if err != nil {
		panic(err)
	}

	key := make([]byte, keyLen)
	r := hkdf.Expand(sha256.New, sharedSecret, info)
	if _, err := io.ReadFull(r, key[:]); err != nil {
		panic(err)
	}

	// Initialize encryption.
	aead, err := encryption.Value(key)
	if err != nil {
		panic(err)
	}

	// Seal the message.
	ciphertext, err := aead.SealWithContext([]byte("message"), encapsulationPublicKey)
	if err != nil {
		panic(err)
	}

	// Sample Output: 04db1267f0c508a21c8e49f2236ec4f219547b32af3714c78fbc8c3f228e62292ed1e2580956d69b87b83c657b28b91a4226d94441e72a89f909e3c1293df22509d2d21795191d54d4af195e5be657f83376b21e0fcca1b4b06ca6a4bfcd20138b1b9195a021abacc3f148cd538ac3ff7d48b6fd137c5fdfb50e2ae94db7846c6b
	fmt.Println(hex.EncodeToString(append(encapsulationPublicKey, ciphertext...)))
}

func ExampleScheme_Decapsulate() {
	// We want to recive a message sent by an anonymous sender.
	receiverPrivateKeyRaw, _ := hex.DecodeString("9b699e0575dbe522a1025aec07f75c4019fc9791a6e9b46e71568e016b76e32e")

	// Received message
	payload, err := hex.DecodeString("040af1c88a36d592729a8c5e40e26b8e0c86d30fb2fa7547a9353f2a4cc95c895ebac81ca4592f51857564e590ff053456e725774544434a537ac7887fc6bacfb9d224e1a850b604ee912cb66df14338d6b05873b04233b0cd31324afa9cb9b5484364198f491e848bb948d5d91bdd440a7f52a66af1ed014eb50704c554e26462")
	if err != nil {
		panic(err)
	}

	// Key agreement exchange algorithm to use. This is a configuration element.
	suite := DHP256HKDFSHA256()
	receiverPrivateKey, _ := suite.DeserializePrivateKey(receiverPrivateKeyRaw)

	sharedSecret, err := suite.Decapsulate(payload[:suite.EncapsulationSize()], receiverPrivateKey)
	if err != nil {
		panic(err)
	}

	// Split the shared secret to extract an encryption key.
	var (
		keyLen    = uint16(32)
		keyLenRaw [2]byte
	)

	// Encode the key length as byte.
	binary.BigEndian.PutUint16(keyLenRaw[:], keyLen)

	// Prepare key split information. It is used to explain why you are
	// splitting a secret.
	info, err := canonicalization.PreAuthenticationEncoding(
		[]byte("unidirectional_message_encryption_key"), // Why
		suite.SuiteID(),                        // How
		receiverPrivateKey.PublicKey().Bytes(), // Who
		keyLenRaw[:],                           // Key size
	)
	if err != nil {
		panic(err)
	}

	key := make([]byte, keyLen)
	r := hkdf.Expand(sha256.New, sharedSecret, info)
	if _, err := io.ReadFull(r, key[:]); err != nil {
		panic(err)
	}

	aead, err := encryption.Value(key)
	if err != nil {
		panic(err)
	}

	cleartext, err := aead.OpenWithContext(payload[suite.EncapsulationSize():], payload[:suite.EncapsulationSize()])
	if err != nil {
		panic(err)
	}

	// Output: message
	fmt.Println(string(cleartext))
}
