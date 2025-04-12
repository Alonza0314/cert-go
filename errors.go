package certgo

import (
	"fmt"
	"os"
	"path/filepath"
)

// CertError 表示证书操作相关的错误
type CertError struct {
	Op  string // 操作名称
	Err error  // 原始错误
}

func (e *CertError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	}
	return e.Op
}

// Unwrap 返回原始错误
func (e *CertError) Unwrap() error {
	return e.Err
}

// NewCertError 创建一个新的证书错误
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

// IsCertError 检查错误是否为CertError类型
func IsCertError(err error) bool {
	var certErr *CertError
	return err != nil && err.Error() == certErr.Error()
}

// IsCertExists 检查错误是否为证书已存在错误
func IsCertExists(err error) bool {
	return err != nil && err.Error() == ErrCertExists.Error()
}

// IsKeyNotFound 检查错误是否为私钥未找到错误
func IsKeyNotFound(err error) bool {
	return err != nil && err.Error() == ErrKeyNotFound.Error()
}

// IsCsrNotFound 检查错误是否为CSR未找到错误
func IsCsrNotFound(err error) bool {
	return err != nil && err.Error() == ErrCsrNotFound.Error()
}

// IsInvalidConfig 检查错误是否为配置无效错误
func IsInvalidConfig(err error) bool {
	return err != nil && err.Error() == ErrInvalidConfig.Error()
}

// IsInvalidCertType 检查错误是否为证书类型无效错误
func IsInvalidCertType(err error) bool {
	return err != nil && err.Error() == ErrInvalidCertType.Error()
}

// WrapFileError 包装文件操作相关的错误
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

// WrapPathError 包装路径相关的错误
func WrapPathError(path string, err error) error {
	if err == nil {
		return nil
	}
	return NewCertError(fmt.Sprintf("invalid path '%s': %v", filepath.Clean(path), err), err)
}
