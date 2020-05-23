// Package cryptowrap JSON/Gob/MsgPack-based Marshaler/Unmarshaler with AES encryption
package cryptowrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"hash/crc32"
)

// WrapperRSA is a struct with custom JSON/Gob/Binary marshaler and unmarshaler.
//
// Marshaler will encrypt Payload with RSA using EncKey as a public key.
// and hash function provided in Hash.
// sha256.New() will be used if no Hash provided.
//
// Serialised data are protected by checksum.
//
// Unmarshaler will decrypt Payload with the DecKeys provided.
// Keys will be tryied one by one until success decryption. Success means checksum check satisfied.
// ErrUndecryptable will be returned in case no one key is suitable.
//
// Label must be the same for Marshaling and Umarshaling. If no label provided empty one is used.
//
// If Compress is true serialized Payload wil be compressed with LZ4.
//
// Note: there is a limit for the length of data could be encrypted with RSA:
// The message must be no longer than the length of the public modulus minus twice the hash length, minus a further 2.
// See https://golang.org/pkg/crypto/rsa/#EncryptOAEP for details (there no much though).
type WrapperRSA struct {
	DecKeys  []*rsa.PrivateKey
	EncKey   *rsa.PublicKey
	Hash     hash.Hash
	Label    []byte
	Payload  interface{}
	Compress bool
}

type externalWrapperRSA struct {
	Payload []byte
}

type internalWrapperRSA struct {
	Compressed bool
	Checksum   uint32
	Payload    []byte
}

type junkWrapperRSA struct {
	Payload interface{}
}

// MarshalJSON is a custom marshaler.
func (w *WrapperRSA) MarshalJSON() ([]byte, error) {
	return w.marshal(json.Marshal)
}

// UnmarshalJSON is a custom unmarshaler.
func (w *WrapperRSA) UnmarshalJSON(data []byte) error {
	return w.unmarshal(data, json.Unmarshal)
}

// GobEncode is a custom marshaler.
func (w *WrapperRSA) GobEncode() ([]byte, error) {
	return w.marshal(gobMarshal)
}

// GobDecode is a custom unmarshaler.
func (w *WrapperRSA) GobDecode(data []byte) error {
	return w.unmarshal(data, gobUnmarshal)
}

// MarshalBinary is a custom marshaler to be used with MsgPack (github.com/ugorji/go/codec).
func (w *WrapperRSA) MarshalBinary() (data []byte, err error) {
	return w.marshal(binMarshal)
}

// UnmarshalBinary is a custom unmarshaler to be used with MsgPack (github.com/ugorji/go/codec).
func (w *WrapperRSA) UnmarshalBinary(data []byte) error {
	return w.unmarshal(data, binUnmarshal)
}

var emptyLabel = []byte("") // nolint: gochecknoglobals

func (w *WrapperRSA) marshal(marshaler func(interface{}) ([]byte, error)) ([]byte, error) {
	var (
		intW  internalWrapperRSA
		junkW junkWrapperRSA
		extW  externalWrapperRSA
		err   error
	)

	if w.Hash == nil {
		w.Hash = sha256.New()
	}

	if w.Label == nil {
		w.Label = emptyLabel
	}

	junkW.Payload = w.Payload

	intW.Payload, err = marshaler(&junkW)
	if err != nil {
		return nil, fmt.Errorf("marshaling payload: %w", err)
	}

	if w.Compress {
		intW.Payload, err = compress(intW.Payload)
		if err != nil {
			return nil, err
		}

		intW.Compressed = true
	}

	intW.Checksum = crc32.ChecksumIEEE(intW.Payload)

	extW.Payload, err = marshaler(&intW)
	if err != nil {
		return nil, fmt.Errorf("marshaling payload wrapper: %w", err)
	}

	extW.Payload, err = rsa.EncryptOAEP(w.Hash, rand.Reader, w.EncKey, extW.Payload, w.Label)
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}

	data, err := marshaler(&extW)
	if err != nil {
		return nil, fmt.Errorf("marshaling: %w", err)
	}

	return data, err
}

func (w *WrapperRSA) unmarshal(data []byte, unmarshaler func([]byte, interface{}) error) error { // nolint: gocyclo
	if len(w.DecKeys) < 1 {
		return ErrNoKey
	}

	if w.Hash == nil {
		w.Hash = sha256.New()
	}

	if w.Label == nil {
		w.Label = emptyLabel
	}

	extW := externalWrapper{}

	err := unmarshaler(data, &extW)
	if err != nil {
		return fmt.Errorf("unmarshaling: %w", err)
	}

	for _, key := range w.DecKeys {
		data, err = rsa.DecryptOAEP(w.Hash, rand.Reader, key, extW.Payload, w.Label)
		if err != nil {
			continue
		}

		intW := internalWrapper{}

		err = unmarshaler(data, &intW)
		if err != nil {
			continue
		}

		checksum := crc32.ChecksumIEEE(intW.Payload)
		if checksum != intW.Checksum {
			continue
		}

		if intW.Compressed {
			intW.Payload, err = decompress(intW.Payload)
			if err != nil {
				return err
			}
		}

		junkW := junkWrapper{
			Payload: w.Payload,
		}

		err = unmarshaler(intW.Payload, &junkW)
		if err != nil {
			return fmt.Errorf("unmarshaling wrapper: %w", err)
		}

		w.Payload = junkW.Payload

		return nil
	}

	return ErrUndecryptable
}
