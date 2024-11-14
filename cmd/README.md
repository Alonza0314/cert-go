# Command Line Tool

## private-key

```bash
used to create private key, you need to specify the key path you want to save

Usage:
  cert-go create private-key [flags]

Flags:
  -h, --help         help for private-key
  -o, --out string   specify the output path of the private key
```

## csr

```bash
used to create csr, you need to specify the configuration yaml file path

Usage:
  cert-go create csr [flags]

Flags:
  -h, --help          help for csr
  -t, --type string   specify the type of the certificate: [intermediate, server, client]
  -y, --yaml string   specify the configuration yaml file path
```
