// Package cryptowrap JSON/Gob/MsgPack-based Marshaler/Unmarshaler with AES encryption
package cryptowrap

import (
	"bytes"
	"crypto/aes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io/ioutil"

	aescrypt "github.com/Djarvur/go-aescrypt"
	"github.com/pierrec/lz4"
	"github.com/ugorji/go/codec"
)

// Errors might be returned. They will be wrapped with stacktrace at least, of course.
var (
	ErrUndecryptable = errors.New("data could not be decrypted")
	ErrNoKey         = errors.New("key has to be provided")
)

// Wrapper is a struct with custom JSON/Gob/Binary marshaler and unmarshaler.
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
//
// If Compress is true serialized Payload wil be compressed with LZ4.
type Wrapper struct {
	Keys     [][]byte
	IV       []byte
	Payload  interface{}
	Compress bool
}

type externalWrapper struct {
	IV      []byte
	Payload []byte
}

type internalWrapper struct {
	Compressed bool
	Checksum   uint32
	Payload    []byte
}

type junkWrapper struct {
	Payload interface{}
	Junk    []byte
}

// MarshalJSON is a custom marshaler.
func (w *Wrapper) MarshalJSON() ([]byte, error) {
	return w.marshal(json.Marshal)
}

// UnmarshalJSON is a custom unmarshaler.
func (w *Wrapper) UnmarshalJSON(data []byte) error {
	return w.unmarshal(data, json.Unmarshal)
}

// GobEncode is a custom marshaler.
func (w *Wrapper) GobEncode() ([]byte, error) {
	return w.marshal(gobMarshal)
}

// GobDecode is a custom unmarshaler.
func (w *Wrapper) GobDecode(data []byte) error {
	return w.unmarshal(data, gobUnmarshal)
}

// MarshalBinary is a custom marshaler to be used with MsgPack (github.com/ugorji/go/codec).
func (w *Wrapper) MarshalBinary() (data []byte, err error) {
	return w.marshal(binMarshal)
}

// UnmarshalBinary is a custom unmarshaler to be used with MsgPack (github.com/ugorji/go/codec).
func (w *Wrapper) UnmarshalBinary(data []byte) error {
	return w.unmarshal(data, binUnmarshal)
}

func (w *Wrapper) marshal(marshaler func(interface{}) ([]byte, error)) ([]byte, error) {
	if len(w.Keys) < 1 {
		return nil, ErrNoKey
	}

	var (
		intW  internalWrapper
		junkW junkWrapper
		extW  externalWrapper
		err   error
	)

	if w.IV == nil {
		w.IV = randBytes(aes.BlockSize)
	}

	junkW.Payload = w.Payload
	junkW.Junk = randBytes(len(w.Keys[0]))

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

	extW.IV = w.IV

	extW.Payload, err = aescrypt.EncryptAESCBCPadded(extW.Payload, w.Keys[0], w.IV)
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}

	data, err := marshaler(&extW)
	if err != nil {
		return nil, fmt.Errorf("marshaling: %w", err)
	}

	return data, err
}

func (w *Wrapper) unmarshal(data []byte, unmarshaler func([]byte, interface{}) error) error {
	if len(w.Keys) < 1 {
		return ErrNoKey
	}

	extW := externalWrapper{}

	err := unmarshaler(data, &extW)
	if err != nil {
		return fmt.Errorf("unmarshaling: %w", err)
	}

	for _, key := range w.Keys {
		data, err = aescrypt.DecryptAESCBCPadded(extW.Payload, key, extW.IV)
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

func compress(data []byte) ([]byte, error) {
	buf := &bytes.Buffer{}

	compressor := lz4.NewWriter(buf)

	_, err := compressor.Write(data)
	if err != nil {
		return nil, fmt.Errorf("compressing: %w", err)
	}

	err = compressor.Close()
	if err != nil {
		return nil, fmt.Errorf("compressing: %w", err)
	}

	return buf.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(data)

	data, err := ioutil.ReadAll(lz4.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("decompressing: %w", err)
	}

	return data, nil
}

func gobMarshal(e interface{}) ([]byte, error) {
	var b bytes.Buffer

	if err := gob.NewEncoder(&b).Encode(e); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func gobUnmarshal(data []byte, e interface{}) error {
	return gob.NewDecoder(bytes.NewBuffer(data)).Decode(e)
}

func binMarshal(e interface{}) ([]byte, error) {
	var b bytes.Buffer

	if err := codec.NewEncoder(&b, new(codec.MsgpackHandle)).Encode(e); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func binUnmarshal(data []byte, e interface{}) error {
	return codec.NewDecoderBytes(data, new(codec.MsgpackHandle)).Decode(e)
}
