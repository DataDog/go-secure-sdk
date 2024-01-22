package hpke

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
)

func ExampleSender_SetupBase() {
	// We want to send a message to a receiver identified by a public key
	// which will be the only one able to read the message.
	receiverPublicKeyRaw, _ := hex.DecodeString("04d356f8ab8351ac9e9268979c7afde9e539c4609e00e95ec60cb5d4df36937049f2e4e4be6c06f9bf66afcebcabfa63bb53969abaa5e25d659c7986e3fd35a757")

	// Initialize HPKE suite
	suite := New(KEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES128GCM)
	kem, _, _ := suite.Params()

	// Decode public key
	receiverPublicKey, err := kem.Scheme().DeserializePublicKey(receiverPublicKeyRaw)
	if err != nil {
		panic(err)
	}

	enc, sealer, err := suite.Sender(receiverPublicKey, []byte("message_encryption")).SetupBase()
	if err != nil {
		panic(err)
	}

	ct, err := sealer.Seal([]byte("message"), enc)
	if err != nil {
		panic(err)
	}

	// Sample Output: 04f5776368a8a5bd011ab47996399d79a65bdf03cd7776d5505ec71ed7e85d1981c3bce7c20464f71a54f1087338986110338bff2ab782b0cc72429169a82911daff3ed5953e61959a6846f20778a09202b1a250a042626d
	fmt.Println(hex.EncodeToString(append(enc, ct...)))
}

func ExampleReceiver_SetupBase() {
	// We want to recive a message sent by an anonymous sender.
	receiverPrivateKeyRaw, _ := hex.DecodeString("9b699e0575dbe522a1025aec07f75c4019fc9791a6e9b46e71568e016b76e32e")
	receiverPrivateKey, _ := ecdh.P256().NewPrivateKey(receiverPrivateKeyRaw)

	// Received message
	payload, err := hex.DecodeString("04f5776368a8a5bd011ab47996399d79a65bdf03cd7776d5505ec71ed7e85d1981c3bce7c20464f71a54f1087338986110338bff2ab782b0cc72429169a82911daff3ed5953e61959a6846f20778a09202b1a250a042626d")
	if err != nil {
		panic(err)
	}

	// Initialize HPKE suite
	suite := New(KEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES128GCM)
	kem, _, _ := suite.Params()

	opener, err := suite.Receiver(receiverPrivateKey, []byte("message_encryption")).SetupBase(payload[:kem.Scheme().EncapsulationSize()])
	if err != nil {
		panic(err)
	}

	pt, err := opener.Open(payload[kem.Scheme().EncapsulationSize():], payload[:kem.Scheme().EncapsulationSize()])
	if err != nil {
		panic(err)
	}

	// Output: message
	fmt.Println(string(pt))
}

func ExampleSender_SetupPSK() {
	// We want to send a message to a receiver identified by a public key and a PSK
	// which will be the only one able to read the message.
	receiverPublicKeyRaw, _ := hex.DecodeString("04d356f8ab8351ac9e9268979c7afde9e539c4609e00e95ec60cb5d4df36937049f2e4e4be6c06f9bf66afcebcabfa63bb53969abaa5e25d659c7986e3fd35a757")

	// Initialize HPKE suite
	suite := New(KEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES128GCM)
	kem, _, _ := suite.Params()

	// Decode public key
	receiverPublicKey, err := kem.Scheme().DeserializePublicKey(receiverPublicKeyRaw)
	if err != nil {
		panic(err)
	}

	var (
		psk   = []byte(`/oe_i,2.[TjBJ<lk"+8fan[Xokqz]t$w/w"-#j^]EKhwV(.<Ezt"Mm+F4_l;LX?`)
		pskID = []byte("preshared-key-1")
	)
	enc, sealer, err := suite.Sender(receiverPublicKey, []byte("message_encryption")).SetupPSK(psk, pskID)
	if err != nil {
		panic(err)
	}

	ct, err := sealer.Seal([]byte("message"), enc)
	if err != nil {
		panic(err)
	}

	// Sample Output: 0413f6d155db82d66be6b73363dfedf77fc13b40e5d48a575fdae48ec83bf7b4d9b9e5184232cea2ed232d082b189f1a92dc320995fe4a5f093157027d9c344648c84ae1e1f98d6dd7eea55bac2c8e15037c26e1cbbf97cf
	fmt.Println(hex.EncodeToString(append(enc, ct...)))
}

//nolint:nogo
func ExampleReceiver_SetupPSK() {
	// We want to recive a message sent by an anonymous sender.
	receiverPrivateKeyRaw, _ := hex.DecodeString("9b699e0575dbe522a1025aec07f75c4019fc9791a6e9b46e71568e016b76e32e")
	receiverPrivateKey, _ := ecdh.P256().NewPrivateKey(receiverPrivateKeyRaw)

	var (
		psk   = []byte(`/oe_i,2.[TjBJ<lk"+8fan[Xokqz]t$w/w"-#j^]EKhwV(.<Ezt"Mm+F4_l;LX?`)
		pskID = []byte("preshared-key-1")
	)

	// Received message
	payload, err := hex.DecodeString("0413f6d155db82d66be6b73363dfedf77fc13b40e5d48a575fdae48ec83bf7b4d9b9e5184232cea2ed232d082b189f1a92dc320995fe4a5f093157027d9c344648c84ae1e1f98d6dd7eea55bac2c8e15037c26e1cbbf97cf")
	if err != nil {
		panic(err)
	}

	// Initialize HPKE suite
	suite := New(KEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES128GCM)
	kem, _, _ := suite.Params()

	opener, err := suite.Receiver(receiverPrivateKey, []byte("message_encryption")).SetupPSK(payload[:kem.Scheme().EncapsulationSize()], psk, pskID)
	if err != nil {
		panic(err)
	}

	pt, err := opener.Open(payload[kem.Scheme().EncapsulationSize():], payload[:kem.Scheme().EncapsulationSize()])
	if err != nil {
		panic(err)
	}

	// Output: message
	fmt.Println(string(pt))
}

func ExampleSender_SetupAuth() {
	// We want to send a message via an authenticated sender to a receiver
	// identified by a public key which will be the only one able to read the
	// message.
	receiverPublicKeyRaw, _ := hex.DecodeString("04d356f8ab8351ac9e9268979c7afde9e539c4609e00e95ec60cb5d4df36937049f2e4e4be6c06f9bf66afcebcabfa63bb53969abaa5e25d659c7986e3fd35a757")
	senderPrivateKeyRaw, _ := hex.DecodeString("42b4fc36610ce331cbb73c28e9611028528ff168b64e36b0de4bcf4fd22346c7")
	senderPrivateKey, _ := ecdh.P256().NewPrivateKey(senderPrivateKeyRaw)

	// Initialize HPKE suite
	suite := New(KEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_ChaCha20Poly1305)
	kem, _, _ := suite.Params()

	// Decode public key
	receiverPublicKey, err := kem.Scheme().DeserializePublicKey(receiverPublicKeyRaw)
	if err != nil {
		panic(err)
	}

	enc, sealer, err := suite.Sender(receiverPublicKey, []byte("message_encryption")).SetupAuth(senderPrivateKey)
	if err != nil {
		panic(err)
	}

	ct, err := sealer.Seal([]byte("message"), enc)
	if err != nil {
		panic(err)
	}

	// Sample Output: 0403cb282dca79e7b89bf4c1e761f32f874e76d19b8116a22491f2acec0772f9d2e39b33e54b47e21ad74f2d6c862f77b0d32af1533ad9ba208b2bdeb23e49aa70c6c135861f213b96eebba1cd45cabb87e7f95a6c3b2e11
	fmt.Println(hex.EncodeToString(append(enc, ct...)))
}

func ExampleReceiver_SetupAuth() {
	// We want to recive a message sent by an anonymous sender.
	receiverPrivateKeyRaw, _ := hex.DecodeString("9b699e0575dbe522a1025aec07f75c4019fc9791a6e9b46e71568e016b76e32e")
	receiverPrivateKey, _ := ecdh.P256().NewPrivateKey(receiverPrivateKeyRaw)
	senderPublicKeyRaw, _ := hex.DecodeString("04e35e8b164b9e4705f1830928e453673ef1a757f753c524e30323f4c85f6c08f850743a742cb49cacb0d4a1fb4779bb2dfb01af0838d6bc098c4be037df80a4cd")

	// Received message
	payload, err := hex.DecodeString("04926ea56c729fe294625f8c8179b033e110a15b70d634393b1c07e7f4791fc45f96ccb5625f2144440bac9a2fd86b62aad3616df90c28035bbe8018bd6b9c2b417e35618347f4e28cc1a2118f1c81ac82dd857dd474cddc")
	if err != nil {
		panic(err)
	}

	// Initialize HPKE suite
	suite := New(KEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_ChaCha20Poly1305)
	kem, _, _ := suite.Params()

	// Decode public key
	senderPublicKey, err := kem.Scheme().DeserializePublicKey(senderPublicKeyRaw)
	if err != nil {
		panic(err)
	}

	opener, err := suite.Receiver(receiverPrivateKey, []byte("message_encryption")).SetupAuth(payload[:kem.Scheme().EncapsulationSize()], senderPublicKey)
	if err != nil {
		panic(err)
	}

	pt, err := opener.Open(payload[kem.Scheme().EncapsulationSize():], payload[:kem.Scheme().EncapsulationSize()])
	if err != nil {
		panic(err)
	}

	// Output: message
	fmt.Println(string(pt))
}

func ExampleSender_SetupAuthPSK() {
	// We want to send a message via an authenticated sender to a receiver
	// identified by a public key which will be the only one able to read the
	// message.
	receiverPublicKeyRaw, _ := hex.DecodeString("04d356f8ab8351ac9e9268979c7afde9e539c4609e00e95ec60cb5d4df36937049f2e4e4be6c06f9bf66afcebcabfa63bb53969abaa5e25d659c7986e3fd35a757")
	senderPrivateKeyRaw, _ := hex.DecodeString("11fe280e6a526dc4d84c6d8d0207411400856a5162b94e22d894624ca58304d9")
	senderPrivateKey, _ := ecdh.P256().NewPrivateKey(senderPrivateKeyRaw)

	var (
		psk   = []byte(`/oe_i,2.[TjBJ<lk"+8fan[Xokqz]t$w/w"-#j^]EKhwV(.<Ezt"Mm+F4_l;LX?`)
		pskID = []byte("preshared-key-1")
	)

	// Initialize HPKE suite
	suite := New(KEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_ChaCha20Poly1305)
	kem, _, _ := suite.Params()

	// Decode public key
	receiverPublicKey, err := kem.Scheme().DeserializePublicKey(receiverPublicKeyRaw)
	if err != nil {
		panic(err)
	}

	enc, sealer, err := suite.Sender(receiverPublicKey, []byte("message_encryption")).SetupAuthPSK(psk, pskID, senderPrivateKey)
	if err != nil {
		panic(err)
	}

	ct, err := sealer.Seal([]byte("message"), enc)
	if err != nil {
		panic(err)
	}

	// Sample Output: 048564b835358a0191cce689bca5aa263e3f61716a60d80b933f6e4c63af7313f9466a4affb80c2356062b62edc763dcbfe5954f29d909661255738ffae13d1e7d84c237b104d444af1e33f852059ba1d30b0179555e568f
	fmt.Println(hex.EncodeToString(append(enc, ct...)))
}

func ExampleReceiver_SetupAuthPSK() {
	// We want to recive a message sent by an anonymous sender.
	receiverPrivateKeyRaw, _ := hex.DecodeString("9b699e0575dbe522a1025aec07f75c4019fc9791a6e9b46e71568e016b76e32e")
	receiverPrivateKey, _ := ecdh.P256().NewPrivateKey(receiverPrivateKeyRaw)
	senderPublicKeyRaw, _ := hex.DecodeString("04d28d7a84854c301196b17f6a6e2c17b66701a6194542e22e28925f447e3490e07beb9f347cac0ad8f41727fd395e1495689abe716b53a5befd298f7ae1cc3833")

	var (
		psk   = []byte(`/oe_i,2.[TjBJ<lk"+8fan[Xokqz]t$w/w"-#j^]EKhwV(.<Ezt"Mm+F4_l;LX?`)
		pskID = []byte("preshared-key-1")
	)

	// Received message
	payload, err := hex.DecodeString("04c7771f3c5a8e6516eec0d7a636e7d6076e82ff7f23d633ff9bbf1e3759ef7dbb1f05a9b044282d7383c011c112fc7e4a6031b7c483d2e5107d4128ed72505b733f9c34e7b35e6712b23cae97b438091af42a2b06a03297")
	if err != nil {
		panic(err)
	}

	// Initialize HPKE suite
	suite := New(KEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_ChaCha20Poly1305)
	kem, _, _ := suite.Params()

	// Decode public key
	senderPublicKey, err := kem.Scheme().DeserializePublicKey(senderPublicKeyRaw)
	if err != nil {
		panic(err)
	}

	opener, err := suite.Receiver(receiverPrivateKey, []byte("message_encryption")).SetupAuthPSK(payload[:kem.Scheme().EncapsulationSize()], psk, pskID, senderPublicKey)
	if err != nil {
		panic(err)
	}

	pt, err := opener.Open(payload[kem.Scheme().EncapsulationSize():], payload[:kem.Scheme().EncapsulationSize()])
	if err != nil {
		panic(err)
	}

	// Output: message
	fmt.Println(string(pt))
}
