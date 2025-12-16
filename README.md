# Otoroshi Coraza Plugin - OWASP Core Rule Set for Otoroshi

This is a WASM module that implements the [OWASP Core Rule Set](https://coreruleset.org/) for Otoroshi using [Coraza](https://github.com/corazawaf/coraza). It follows the Otoroshi WASM plugin ABI to provide a simple way to integrate the OWASP Core Rule Set into Otoroshi.

# Dependencies

- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)
- [Coraza](https://github.com/corazawaf/coraza)

## Build

```
GOOS=wasip1 GOARCH=wasm go build -o coraza.wasm coraza.go
```

