package authorization

import (
	"context"
	"fmt"

	"github.com/DataDog/go-secure-sdk/authorization/testdata"
)

func ExampleOpaBundle() {
	// Initialize the authorizer.
	authz, err := OpaBundle(context.Background(), testdata.Policies)
	if err != nil {
		panic(err)
	}

	// Authorize a request.
	resp, err := authz.Can(context.Background(), &Request{
		// Action to be executed on the resource.
		Action: "table:delete",
		// Resource to be acted upon.
		Resource: KV{
			"kind": "datadoghq.com/reference-table",
			"id":   "security-ambassadors",
		},
		// User identity from service authentication.
		User: KV{
			"subject": "user:123",
			"groups":  []string{"administrators"},
		},
		// Client identity (if available).
		Client: KV{
			"subject": "ambassad-cli",
		},
	})
	if err != nil {
		panic(err)
	}

	// Output: true
	fmt.Println(resp.Allow)
}
