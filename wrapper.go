package cryptowrap

import (
	"crypto/aes"
	"encoding/json"
	"hash/crc32"

	"github.com/pkg/errors"
)

// Errors might be returned. They will be wrapped with stacktrace at least, of course.
var (
	ErrUndecryptable = errors.New("data could not be decrypted")
	ErrNoKey         = errors.New("key has to be provided")
)

// Wrapper is a struct with custom JSON marshaler and unmarshaler.
//
// Marshaler will encrypt Payload with AES using first value from Keys as a key
// and provided IV as an initialisation vector.
// Random string will be used if no IV provided.
//
// Actual AES form will be chosen based on first Keys value length.
//
// Serialised data are protected by checksum.
//
// Unmarshaler will decrypt Payload with the Keys provided.
// Keys will be tryied one by one until success decryption. Success means checksum check satisfied.
// ErrUndecryptable will be returned in case no one key is suitable.
type Wrapper struct {
	Keys    [][]byte
	IV      []byte
	Payload interface{}
}

type externalWrapper struct {
	IV      []byte
	Payload []byte
}

type internalWrapper struct {
	Checksum uint32
	Payload  []byte
}

type junkWrapper struct {
	Payload interface{}
	Junk    []byte
}

// MarshalJSON is a custom marshaler
func (w *Wrapper) MarshalJSON() ([]byte, error) {
	if len(w.Keys) < 1 {
		return nil, errors.WithStack(ErrNoKey)
	}

	var (
		intW  internalWrapper
		junkW junkWrapper
		extW  externalWrapper
		err   error
	)

	if w.IV == nil {
		w.IV, err = RandBytes(aes.BlockSize)
		if err != nil {
			return nil, errors.Wrap(err, "reading random")
		}
	}

	junkW.Payload = w.Payload
	junkW.Junk, err = RandBytes(len(w.Keys[0]))
	if err != nil {
		return nil, errors.Wrap(err, "reading random")
	}

	intW.Payload, err = json.Marshal(&junkW)
	if err != nil {
		return nil, errors.Wrap(err, "marshaling payload")
	}
	intW.Checksum = crc32.ChecksumIEEE(intW.Payload)

	extW.Payload, err = json.Marshal(&intW)
	if err != nil {
		return nil, errors.Wrap(err, "marshaling payload wrapper")
	}
	extW.IV = w.IV

	extW.Payload, err = EncryptAESCBCpad(extW.Payload, w.Keys[0], w.IV)
	if err != nil {
		return nil, errors.Wrap(err, "encrypting")
	}

	data, err := json.Marshal(&extW)
	if err != nil {
		return nil, errors.Wrap(err, "marshaling")
	}

	return data, err
}

// UnmarshalJSON is a custom unmarshaler
func (w *Wrapper) UnmarshalJSON(data []byte) error {
	if len(w.Keys) < 1 {
		return errors.WithStack(ErrNoKey)
	}

	extW := externalWrapper{}
	err := json.Unmarshal(data, &extW)
	if err != nil {
		return errors.Wrap(err, "unmarshaling")
	}

	for _, key := range w.Keys {
		data, err = DecryptAESCBCunpad(extW.Payload, key, extW.IV)
		if err != nil {
			continue
		}

		intW := internalWrapper{}
		err = json.Unmarshal(data, &intW)
		if err != nil {
			continue
		}

		checksum := crc32.ChecksumIEEE(intW.Payload)
		if checksum != intW.Checksum {
			continue
		}

		junkW := junkWrapper{
			Payload: w.Payload,
		}

		err = json.Unmarshal(intW.Payload, &junkW)
		if err != nil {
			return errors.Wrap(err, "unmarshaling wrapper")
		}

		w.Payload = junkW.Payload
		return nil
	}

	return errors.WithStack(ErrUndecryptable)
}
