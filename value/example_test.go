package value

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/DataDog/go-secure-sdk/value/transformer"
)

func ExampleAsWrapped() {
	// Prepare an event to log
	type event struct {
		Timestamp time.Time `json:"@timestamp"`
		Level     string    `json:"@level"`
		Message   any
	}

	// Assign specific global tokenization key
	if err := SetDefaultTokenizationKey([]byte("000-deterministic-tokenization-key")); err != nil {
		panic(err)
	}

	// Prepare explicit secret leak
	type login struct {
		Principal Wrapped[string]  `json:"principal"`
		Secret    Redacted[string] `json:"secret"`
	}

	out, err := json.Marshal(&event{
		Timestamp: time.Date(2023, time.March, 8, 15, 25, 18, 123, time.UTC),
		Level:     "info",
		Message: &login{
			Principal: AsWrapped("user", transformer.Hash(sha256.New)),
			Secret:    AsRedacted("should not be logged"),
		},
	})
	if err != nil {
		panic(err)
	}

	// Output: {"@timestamp":"2023-03-08T15:25:18.000000123Z","@level":"info","Message":{"principal":"MZDSYdGGrurTqN7sICc3x3da9cjUVanlupWMSLX9P1k","secret":"[redacted]"}}
	fmt.Println(string(out))
}

func ExampleAsEncrypted() {
	// Prepare a configuration state
	type credentials struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}

	type configuration struct {
		Server      string               `json:"server"`
		Credentials Wrapped[credentials] `json:"credentials"`
	}

	out, err := json.Marshal(&configuration{
		Server: "pgsql://127.0.0.1:5432/production",
		Credentials: AsEncrypted(credentials{
			User:     "app-runner-12345",
			Password: "secret password",
		}),
	})
	if err != nil {
		panic(err)
	}

	// Sample Output: {"server":"pgsql://127.0.0.1:5432/production","credentials":"0tZUAiEGkBzhRPoIrRtntDuojTTBJ-ekwgG4ShvyCOA5RcPGS6_L-O8gkDVCEI6FMSIP4dpVRrHUYSFq7o0GSH08GcQA-dlP3ohSOam1mxd-SYqMq8Mzmr5johGd7Gtl7u-c2KNLG3m1hMexl76iXbQ"}
	fmt.Println(string(out))
}

func ExampleAsRedacted() {
	// Use a strong type to represents secret value
	var secret Redacted[string]

	// Assign the secret value
	secret.value = "password"

	// Output:
	// password
	// [redacted]
	fmt.Printf("%s\n%s", secret.Unwrap(), secret)
}

func ExampleAsToken() {
	// Assign specific global tokenization key
	if err := SetDefaultTokenizationKey([]byte("000-deterministic-tokenization-key")); err != nil {
		panic(err)
	}

	// Use a strong type to represents secret value
	secret := AsToken("firstname.lastname@company.tld")

	// Output:
	// firstname.lastname@company.tld
	// m9BAmfJ5duXmaIn2IKW1VuFP60ZlFFuJBTD1Ytp6eKQ
	fmt.Printf("%s\n%s", secret.Unwrap(), secret)
}
