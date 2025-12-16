# OWASP Core Rule Set for Otoroshi

This is a WASM module that implements the [OWASP Core Rule Set](https://coreruleset.org/) for Otoroshi. It follows the Otoroshi WASM plugin ABI to provide a simple way to integrate the OWASP Core Rule Set into Otoroshi.

# Dependencies

- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)

## Build

```
GOOS=wasip1 GOARCH=wasm go build -o coraza.wasm coraza.go
```

