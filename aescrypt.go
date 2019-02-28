package cryptowrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"

	"github.com/pkg/errors"
)

// Errors might be returned. They will be wrapped with stacktrace at least, of course.
var (
	// Panic was recovered. Will be wrapped with actual panic message.
	ErrRecovered = errors.New("recovered")

	// Data provided are invalid. Will be wrapped with actual error message.
	ErrInvalidInput = errors.New("invalid input")
)

// DecryptAESCBCunpad will decrypt your data and trim the padding.
func DecryptAESCBCunpad(src, key, iv []byte) ([]byte, error) {
	dst, err := DecryptAESCBC(src, key, iv)
	if err != nil {
		return dst, err
	}
	return Pkcs7Unpad(dst, len(key))
}

// DecryptAESCBC will decrypt your data.
func DecryptAESCBC(src, key, iv []byte) (dst []byte, err error) {
	defer catch(&err)

	dst = make([]byte, len(src))

	cip, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	cipher.NewCBCDecrypter(cip, iv).CryptBlocks(dst, src)

	return dst, nil
}

// EncryptAESCBCpad will pad your data and encrypt them.
func EncryptAESCBCpad(src, key, iv []byte) ([]byte, error) {
	src, err := Pkcs7Pad(src, len(key))
	if err != nil {
		return nil, err
	}
	return EncryptAESCBC(src, key, iv)
}

// EncryptAESCBC will encrypt your data.
func EncryptAESCBC(src, key, iv []byte) ([]byte, error) {
	dst := make([]byte, len(src))

	cip, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	c := cipher.NewCBCEncrypter(cip, iv)
	c.CryptBlocks(dst, src)

	return dst, nil
}

// Pkcs7Pad will pad your data.
func Pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, errors.Wrapf(ErrInvalidInput, "invalid blocklen %d", blocklen)
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen++
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

// Pkcs7Unpad will trim the padding from your data.
func Pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, errors.Wrapf(ErrInvalidInput, "invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, errors.Wrapf(ErrInvalidInput, "invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, errors.Wrapf(ErrInvalidInput, "invalid padding for %d bytes: %d > %d or %d == 0", len(data), padlen, blocklen, padlen)
	}
	// check padding
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, errors.Wrapf(ErrInvalidInput, "invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}

func catch(err *error) {
	e := recover()
	if e != nil {
		if errInternal, ok := e.(error); ok {
			*err = errors.WithStack(errInternal)
		} else {
			*err = errors.Wrapf(ErrRecovered, "%v", e)
		}
	}
}
