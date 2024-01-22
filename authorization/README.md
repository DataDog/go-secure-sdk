# authorization

Package authorization provides a simple interface for authorization.

## Types

### type [Authorizer](api.go#L8)

`type Authorizer interface { ... }`

Authorizer is the interface that wraps the basic Can method.

#### func [AllowAll](allow_all.go#L6)

`func AllowAll() Authorizer`

AllowAll returns an Authorizer that allows all actions on all resources.

#### func [OpaBundle](opa_bundle.go#L16)

`func OpaBundle(ctx context.Context, rootFs fs.FS) (Authorizer, error)`

OpaBundle returns an Authorizer that uses an OPA bundle to authorize actions on resources.

```golang
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
```

 Output:

```
true
```

### type [Decision](api.go#L66)

`type Decision struct { ... }`

Decision is the structure that wraps the information about a rule that was
evaluated during an authorization request.

### type [KV](api.go#L13)

`type KV map[string]any`

KV is a map of string to any.

### type [Request](api.go#L17)

`type Request struct { ... }`

Request is the structure that wraps the information needed to authorize an
action on a resource.

### type [Response](api.go#L53)

`type Response struct { ... }`

Response is the structure that wraps the result of an authorization request.

