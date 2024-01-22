package encryption

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"sync"

	"github.com/DataDog/go-secure-sdk/generator/randomness"
)

func ExampleValue() {
	key := []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB")

	// Generate a ciphertext
	f, err := Value(key)
	if err != nil {
		panic(err)
	}

	// Create a session content which will be encrypted.
	// We want to protect the state value from being revealed and tampered.
	session := []byte(`{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}`)

	// To prevent encrypted content tampering, we are going to inject additional data
	// to bind the encrypted context to a specific context.
	sealCtx := [][]byte{
		[]byte("oauth-state-csrf-session"),                       // Why are you using the encryption algorithm
		[]byte(`{"uid":"8f41b712-663f-48a8-b43c-54cf97a94d1a"}`), // UserID binding to ensure that the decryption is made with the exact same userID
	}

	// Simulate an encrypted cookie value bound to user ID to prevent cookie swapping.
	ciphertext, err := f.SealWithContext(session, sealCtx...)
	if err != nil {
		panic(err)
	}

	// Try to open session cookie value with all known keys
	plaintext, err := f.OpenWithContext(ciphertext, sealCtx...)
	if err != nil {
		panic(err)
	}

	// Output: {"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}
	fmt.Printf("%s", string(plaintext))
}

func ExampleConvergent() {
	key := []byte("zzTPjjOhqexyMKXAxbelXOZI2lW7VM79kQXEWRPkvMnaWzlJbN1prxEk02huCpD1")

	// Generate a ciphertext
	f, err := Convergent(key)
	if err != nil {
		panic(err)
	}

	// We are going to encrypt the given email.This email will be stored in a database
	// and lookup will be possible from the encrypted form directly.
	pii := []byte("firstname.lastname@company.com")

	ciphertext, err := f.Seal(pii)
	if err != nil {
		panic(err)
	}

	// Output: 1dtoaXXECDRvszKGTnXWpvipYTUgS36vKaWDSkcJrYcgF3M9Rh5bM2tPaBC33Ws/X9gGAqfGkLsU4L0
	fmt.Printf("%s", base64.RawStdEncoding.EncodeToString(ciphertext))
}

func ExampleChunked() {
	key := []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB")

	// Generate a ciphertext
	f, err := Chunked(key)
	if err != nil {
		panic(err)
	}

	// Create stream pipeline
	pr, pw := io.Pipe()

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		// Create writer pipeline to directly encode the encrypted output as
		// a Base64 encoded stream
		b64 := base64.NewEncoder(base64.StdEncoding, pw)

		// Create a fake file content stream (limited to 10MB)
		fileContentReader := io.LimitReader(randomness.NewReader(1), 10<<20)
		_, err := io.Copy(b64, fileContentReader)

		defer b64.Close()
		defer pw.CloseWithError(err)
		defer wg.Done()
	}()

	buf := &bytes.Buffer{}
	if err := f.Seal(buf, pr); err != nil {
		panic(err)
	}

	wg.Wait()

	// Output: 13985326
	fmt.Println(buf.Len())
}

func ExampleValueWithMode() {
	key := []byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB")

	// Generate a ciphertext with FIPS compliant cipher suite
	f, err := ValueWithMode(FIPS, key)
	if err != nil {
		panic(err)
	}

	// Create a session content
	session := []byte(`{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}`)
	sealCtx := []byte(`{"uid":"8f41b712-663f-48a8-b43c-54cf97a94d1a"}`)

	// Simulate an encrypted cookie value bound to user ID to prevent cookie swapping.
	ciphertext, err := f.SealWithContext(session, sealCtx)
	if err != nil {
		panic(err)
	}

	// Try to open session cookie value with all known keys
	plaintext, err := f.OpenWithContext(ciphertext, sealCtx)
	if err != nil {
		panic(err)
	}

	// Output: {"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}
	fmt.Printf("%s", string(plaintext))
}

func ExampleOpen() {
	// Loaded previous keys from secure storage
	keys := [][]byte{
		[]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
		[]byte("RWZLutMaZj6ea3Bf6FqGVoFquuE5jqyN"),
		[]byte("ATCkaljMhYokvN08nZMX358JwPGY4DY0"),
	}

	// Generate a ciphertext
	f, err := Value(keys[0])
	if err != nil {
		panic(err)
	}

	// Create a session content which will be encrypted.
	// We want to protect the state value from being revealed and tampered.
	session := []byte(`{"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}`)

	// To prevent encrypted content tampering, we are going to inject additional data
	// to bind the encrypted context to a specific context.
	sealCtx := []byte(`{"uid":"8f41b712-663f-48a8-b43c-54cf97a94d1a"}`)

	// Simulate an encrypted cookie value bound to user ID to prevent cookie swapping.
	ciphertext, err := f.SealWithContext(session, sealCtx)
	if err != nil {
		panic(err)
	}

	// Try to open session cookie value with all known keys
	plaintext, err := Open(keys, ciphertext, sealCtx)
	if err != nil {
		panic(err)
	}

	// Output: {"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}
	fmt.Printf("%s", string(plaintext))
}

func ExampleRotateKey() {
	// Loaded previous keys from secure storage
	oldKeys := [][]byte{
		[]byte("sQU8SWrSiaz0eewSS9INE1gDGv1nULsB"),
		[]byte("RWZLutMaZj6ea3Bf6FqGVoFquuE5jqyN"),
	}
	newKey := []byte("ATCkaljMhYokvN08nZMX358JwPGY4DY0")

	// Create a session content
	encryptedSession, err := hex.DecodeString("d222128e50db137866a225e61693a072904f38599f37517753307f9e32aa4cd847c2cd8e431b41839def11cec80df9afa88ca919b2b54a3a146318d9297a70e24138e5ee21e7f3f96bd33908baf4fd43e6a3b4c701b19faa6927d09bba8cdfc4a577e03f7c")
	if err != nil {
		panic(err)
	}

	// Provides additional data for ciphertext authentication.
	sealCtx := []byte(`{"uid":"8f41b712-663f-48a8-b43c-54cf97a94d1a"}`)

	// Generate a ciphertext
	newciphertext, err := RotateKey(oldKeys, newKey, encryptedSession, sealCtx)
	if err != nil {
		panic(err)
	}

	// Try to open session cookie value with all known keys
	plaintext, err := Open([][]byte{newKey}, newciphertext, sealCtx)
	if err != nil {
		panic(err)
	}

	// Output: {"state":"gInhnZvpFdKJ2pg7gwPeVuKFZJMNUNNo"}
	fmt.Printf("%s", string(plaintext))
}
