package model

type CertificateAuthority struct {
	Root         Certificate `yaml:"root"`
	Intermediate Certificate `yaml:"intermediate"`
	Server       Certificate `yaml:"server"`
	Client       Certificate `yaml:"client"`
}
