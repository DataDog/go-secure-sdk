package password

import "fmt"

func ExampleNew() {
	// Use a pepper seed to increase password bruteforce in a potential data leak.
	// This value should be stored in your secret storage.
	serverPepperSeed := []byte(`pqIuaay0eBymivqgmpY6oJ5szDOKMoIWCAM8vXmWVm9Lwj4xwVymOAjsN0HTeA1`)

	// Create a new password hasher instance
	h, err := New(
		// Enable FIPS compliance strategy
		WithFIPSCompliance(),
		// Enable password peppering for defense in depth
		WithPepper(serverPepperSeed),
	)
	if err != nil {
		panic(err)
	}

	// Encode the given password
	encoded, err := h.Hash([]byte("my-secure-password"))
	if err != nil {
		panic(err)
	}

	// Sample output: hAIBWCAq6kKaWJde0I5t5cVy0FwWeNWA25YoOWRwMchIQY9PSVhAoYeasejuFGiBLmRJ6DVd7I+7W8ohy5AMmWC10J56eV4k7AYf3emuHQeLux1SX96DeNWp12qo5wuhoOPHWFLbAA
	fmt.Println(encoded)
}
