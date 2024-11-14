# Example

## Create Private Key

In this example, we will create a private key and save it to the `./private_key.pem` file.

[Click here to see the example](./privateKey/)

## Create Csr

In this example, we will create a csr and save it to the `./csr.pem` file. Before creating the csr, we need to prepare the configuration file `./createCsrCfg.yml`.

[Click here to see the example](./csr/)

## Sign Certificate

In this example, we will sign the root certificate and save it to the `./root_cert.pem` file. Before signing the certificate, we need to prepare the configuration file `./signCertCfg.yml`.

As we demonstrate how to sign the root certificate, for intermediate or end-entity certificate, it is the same process except the sign function name:

```go
SignRootCertificate(yamlPath string) ([]byte, error)
SignIntermediateCertificate(yamlPath string) ([]byte, error)
SignServerCertificate(yamlPath string) ([]byte, error)
SignClientCertificate(yamlPath string) ([]byte, error)
```

[Click here to see the example](./cert/)
