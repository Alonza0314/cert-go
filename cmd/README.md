# Command Line Tool

## private-key

```bash
used to create private key, you need to specify the key path you want to save

Usage:
  cert-go create private-key [flags]

Flags:
  -f, --force        overwrite the private key if it already exists
  -h, --help         help for private-key
  -o, --out string   specify the output path of the private key
```

## csr

```bash
used to create csr, you need to specify the configuration yaml file path

Usage:
  cert-go create csr [flags]

Flags:
  -f, --force         overwrite the csr if it already exists
  -h, --help          help for csr
  -t, --type string   specify the type of the certificate: [intermediate, server, client]
  -y, --yaml string   specify the configuration yaml file path
```

## certificate

```bash
used to create certificate, you need to specify the configuration yaml file path

Usage:
  cert-go create cert [flags]

Flags:
  -f, --force         overwrite the certificate if it already exists
  -h, --help          help for cert
  -t, --type string   specify the type of the certificate: [root, intermediate, server, client]
  -y, --yaml string   specify the configuration yaml file path
```
## Additional Notes

- 🔐 **Root CSR Not Generated:**  
  When generating a root certificate (`type: root`), even if a `csr:` field is specified in the YAML file, the CSR file will **not** be saved to disk. This is by design, as root certificates are typically self-signed and do not require a CSR for issuance.

- 📝 **CSR Output for Other Types:**  
  For all other types (`intermediate`, `server`, `client`), if a `csr:` field is specified, `cert-go` will generate and persist a CSR to the given path. This CSR can be reused in other systems or for manual inspection.

- 🧪 **Verifying the Chain:**  
  After generating certificates, you can use `openssl` to verify the validity of the certificate chain manually:

  ```bash
  openssl verify -CAfile root/root.cert.pem \
                 -untrusted intermediate/intermediate.cert.pem \
                 server/server.cert.pem
