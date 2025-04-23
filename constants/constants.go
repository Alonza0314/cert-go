package constants

type CertType string
type PrivateKeyType string

const (
	CERT_TYPE_ROOT         CertType = "root"
	CERT_TYPE_INTERMEDIATE CertType = "intermediate"
	CERT_TYPE_SERVER       CertType = "server"
	CERT_TYPE_CLIENT       CertType = "client"

	PRIVATE_KEY_TYPE_ECDSA   PrivateKeyType = "EC PRIVATE KEY"
	PRIVATE_KEY_TYPE_RSA     PrivateKeyType = "RSA PRIVATE KEY"
	PRIVATE_KEY_TYPE_UNKNOWN PrivateKeyType = "UNKNOWN"
	PRIVATE_KEY_LENGTH       int            = 4096
)
