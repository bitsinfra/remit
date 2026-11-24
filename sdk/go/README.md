# Remit Go SDK

A Sender SDK for [Remit](https://github.com/bitsinfra/remit): agents exchange
programs, not messages. It implements JSON canonicalization (RFC 8785),
`remit_id`, Remit Type capacity, `did:key` identities, DSSE signing, RFC 9421
request signatures and a client that submits remits and verifies receipts. It has
no dependencies outside the standard library.

```bash
go get github.com/bitsinfra/remit/sdk/go
```

```go
import "github.com/bitsinfra/remit/sdk/go/remit"

id, err := remit.LoadIdentity("keys/agent.json")
if err != nil {
	log.Fatal(err)
}
holder, err := remit.NewClient(id).Holder(ctx, "https://crm.example.com", "") // verifies the signed catalog
if err != nil {
	log.Fatal(err)
}

returns := map[string]any{"list": map[string]any{"max": 20, "of": map[string]any{"struct": map[string]any{
	"region": map[string]any{"enum": []string{"AMER", "APAC", "EMEA"}},
	"arr":    map[string]any{"float": map[string]any{"min": 0, "max": 1e10, "precision": 1000}},
}}}}
res, err := holder.Query(ctx, "SELECT region, SUM(arr) AS arr FROM crm.accounts GROUP BY region", returns, nil, "")
if err != nil {
	log.Fatal(err) // *remit.Error carries the decision and structured diagnostics
}
fmt.Println(string(res.Value), res.Receipt["result_sha256"])
```

`Holder.Kernel` submits a kernel with declared reads; `Holder.Check` asks for an
admission decision without running anything.

Tests run the shared conformance vectors from the repository's `spec/conformance`:

```bash
go vet ./... && go test ./...
```

## License

Apache-2.0
