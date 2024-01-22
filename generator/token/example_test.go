package token

import (
	"fmt"

	"github.com/google/uuid"
)

func ExampleVerifiableRandom() {
	tokenGenerator := VerifiableRandom()

	// Generate a verifiable string with a given prefix.
	token, err := tokenGenerator.Generate(WithTokenPrefix("ddk"))
	if err != nil {
		panic(err)
	}

	// Sample: ddk_0bNjIQmMJTJSYbSNDer5G8RunHcJWRO7Ukgf
	fmt.Println(token)

	// Verify the token format correctness and then do the database lookup to
	// ensure the token authenticity
	if err := tokenGenerator.Verify(token); err != nil {
		panic(err)
	}
}

func ExampleVerifiableRandomWithPurpose() {
	tokenGenerator := VerifiableRandomWithPurpose("lost-credentials-action-token")

	// Generate a verifiable string associated to the given purpose.
	token, err := tokenGenerator.Generate()
	if err != nil {
		panic(err)
	}

	// Sample: 0jl9s3pHvYKf9YhXhG92CfnwLbEwpeEocMim
	fmt.Println(token)

	// Verify the token format correctness and then do the database lookup to
	// ensure the token authenticity
	if err := tokenGenerator.Verify(token); err != nil {
		panic(err)
	}
}

func ExampleVerifiableUUIDGenerator() {
	// Generate an UUIDv4 (random)
	uid := uuid.Must(uuid.NewRandom())

	// Wrap the given UUID
	tokenGenerator := VerifiableUUIDGenerator(
		StaticUUIDSource(uid),
		[]byte("my-token-super-secret-key"),
	)

	// Generate a verifiable string associated to the given purpose.
	token, err := tokenGenerator.Generate(
		WithTokenPrefix("ddogat"),
	)
	if err != nil {
		panic(err)
	}

	// Sample output: ddogat_3xGv8m7Ee2UVOk7WnFOBCE_1d8lq12WNjZlsdGKF4q0GJZd7hUhnLbyjQhVrTeD1SO6DYzgQ2eRDNM1zjWU
	fmt.Println(token)
}

func ExampleVerifiableUUIDVerifier() {
	// Prepare the verifier
	tokenVerifier := VerifiableUUIDVerifier(
		[]byte("my-token-super-secret-key"),
	)

	t := "ddogat_3xGv8m7Ee2UVOk7WnFOBCE_1d8lq12WNjZlsdGKF4q0GJZd7hUhnLbyjQhVrTeD1SO6DYzgQ2eRDNM1zjWU"

	// Verifiy and extract the UUID
	uid, err := tokenVerifier.Extract(t)
	if err != nil {
		panic(err)
	}

	u, err := uuid.FromBytes(uid)
	if err != nil {
		panic(err)
	}

	// Output: 746c1439-b380-429e-9d53-6bf1b7507c10
	fmt.Println(u)
}
