package certgo

type CertType string

const (
	CERT_TYPE_ROOT         CertType = "root"
	CERT_TYPE_INTERMEDIATE CertType = "intermediate"
	CERT_TYPE_SERVER       CertType = "server"
	CERT_TYPE_CLIENT       CertType = "client"
)
