package certgo

import (
	"fmt"
	"os"
	"path/filepath"
)

// CertError represents certificate operation related errors
type CertError struct {
	Op  string // Operation name
	Err error  // Original error
}

func (e *CertError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	}
	return e.Op
}

// Unwrap returns the original error
func (e *CertError) Unwrap() error {
	return e.Err
}

// NewCertError creates a new certificate error
func NewCertError(op string, err error) error {
	if err == nil {
		return nil
	}
	return &CertError{
		Op:  op,
		Err: err,
	}
}

// Common errors
var (
	ErrCertExists      = &CertError{Op: "certificate already exists"}
	ErrKeyNotFound     = &CertError{Op: "private key not found"}
	ErrCsrNotFound     = &CertError{Op: "CSR not found"}
	ErrInvalidConfig   = &CertError{Op: "invalid configuration"}
	ErrInvalidCertType = &CertError{Op: "invalid certificate type"}
	ErrFileWrite       = &CertError{Op: "failed to write file"}
	ErrFileRead        = &CertError{Op: "failed to read file"}
	ErrFileCreate      = &CertError{Op: "failed to create file"}
	ErrDirCreate       = &CertError{Op: "failed to create directory"}
	ErrInvalidPath     = &CertError{Op: "invalid path"}
	ErrInvalidIP       = &CertError{Op: "invalid IP address"}
	ErrInvalidURI      = &CertError{Op: "invalid URI"}
	ErrInvalidPeriod   = &CertError{Op: "invalid validity period"}
	ErrMissingField    = &CertError{Op: "missing required field"}
)

// IsCertError checks if the error is a CertError type
func IsCertError(err error) bool {
	var certErr *CertError
	return err != nil && err.Error() == certErr.Error()
}

// IsCertExists checks if the error is a certificate already exists error
func IsCertExists(err error) bool {
	return err != nil && err.Error() == ErrCertExists.Error()
}

// IsKeyNotFound checks if the error is a private key not found error
func IsKeyNotFound(err error) bool {
	return err != nil && err.Error() == ErrKeyNotFound.Error()
}

// IsCsrNotFound checks if the error is a CSR not found error
func IsCsrNotFound(err error) bool {
	return err != nil && err.Error() == ErrCsrNotFound.Error()
}

// IsInvalidConfig checks if the error is an invalid configuration error
func IsInvalidConfig(err error) bool {
	return err != nil && err.Error() == ErrInvalidConfig.Error()
}

// IsInvalidCertType checks if the error is an invalid certificate type error
func IsInvalidCertType(err error) bool {
	return err != nil && err.Error() == ErrInvalidCertType.Error()
}

// WrapFileError wraps file operation related errors
func WrapFileError(op string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case os.IsNotExist(err):
		return NewCertError(op+": file not found", err)
	case os.IsPermission(err):
		return NewCertError(op+": permission denied", err)
	default:
		return NewCertError(op, err)
	}
}

// WrapPathError wraps path related errors
func WrapPathError(path string, err error) error {
	if err == nil {
		return nil
	}
	return NewCertError(fmt.Sprintf("invalid path '%s': %v", filepath.Clean(path), err), err)
}
