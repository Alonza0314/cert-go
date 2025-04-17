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
