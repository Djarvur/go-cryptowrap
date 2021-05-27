package cryptowrap_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"encoding/json"
	"fmt"

	"github.com/Djarvur/cryptowrap"
	"github.com/fxamacker/cbor/v2"
	"github.com/ugorji/go/codec"
)

func Example_direct() {
	key := []byte("0123456789ABCDEF")

	src := "hello!"

	data, err := json.Marshal(&cryptowrap.Wrapper{Keys: [][]byte{key}, Payload: &src})
	if err != nil {
		panic(err)
	}

	//	var onTheGo interface{}
	//
	//	err = json.Unmarshal(data, &onTheGo)
	//	if err != nil {
	//		panic(err)
	//	}
	//
	//	log.Printf("payload is encrypted: %v\n", onTheGo)

	var dst string

	err = json.Unmarshal(data, &cryptowrap.Wrapper{Keys: [][]byte{key}, Payload: &dst})
	if err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", dst)
	// Output: hello!
}

func Example_embeded() {
	type toPass struct {
		Insecure string
		Secure   cryptowrap.Wrapper
	}

	type toPassSecure struct {
		Field string
	}

	key := []byte("0123456789ABCDEF")

	srcSecure := toPassSecure{"world!"}

	src := toPass{
		Insecure: "hello",
		Secure: cryptowrap.Wrapper{
			Keys:    [][]byte{key},
			Payload: &srcSecure,
		},
	}

	data, err := json.Marshal(&src)
	if err != nil {
		panic(err)
	}

	//	var onTheGo interface{}
	//
	//	err = json.Unmarshal(data, &onTheGo)
	//	if err != nil {
	//		panic(err)
	//	}
	//
	//	log.Printf("payload is encrypted: %v\n", onTheGo)

	var dstSecure toPassSecure

	dst := toPass{
		Secure: cryptowrap.Wrapper{
			Keys:    [][]byte{key},
			Payload: &dstSecure,
		},
	}

	err = json.Unmarshal(data, &dst)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", dst.Secure.Payload.(*toPassSecure).Field)
	// Output: world!
}

func Example_gob() {
	type toPass struct {
		Insecure string
		Secure   cryptowrap.Wrapper
	}

	type toPassSecure struct {
		Field string
	}

	key := []byte("0123456789ABCDEF")

	srcSecure := toPassSecure{"hello world!"}

	src := toPass{
		Insecure: "hello",
		Secure: cryptowrap.Wrapper{
			Keys:    [][]byte{key},
			Payload: &srcSecure,
		},
	}

	gob.Register(&srcSecure)

	var b bytes.Buffer

	err := gob.NewEncoder(&b).Encode(&src)
	if err != nil {
		panic(err)
	}

	data := b.Bytes()

	var dstSecure toPassSecure

	dst := toPass{
		Secure: cryptowrap.Wrapper{
			Keys:    [][]byte{key},
			Payload: &dstSecure,
		},
	}

	err = gob.NewDecoder(bytes.NewBuffer(data)).Decode(&dst)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", dst.Secure.Payload.(*toPassSecure).Field)
	// Output: hello world!
}

func Example_cbor() {
	type toPass struct {
		Insecure string
		Secure   cryptowrap.Wrapper
	}

	type toPassSecure struct {
		Field string
	}

	key := []byte("0123456789ABCDEF")

	srcSecure := toPassSecure{"hello world!"}

	src := toPass{
		Insecure: "hello",
		Secure: cryptowrap.Wrapper{
			Keys:    [][]byte{key},
			Payload: &srcSecure,
		},
	}

	data, err := cbor.Marshal(&src)
	if err != nil {
		panic(err)
	}

	var dstSecure toPassSecure

	dst := toPass{
		Secure: cryptowrap.Wrapper{
			Keys:    [][]byte{key},
			Payload: &dstSecure,
		},
	}

	err = cbor.Unmarshal(data, &dst)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", dst.Secure.Payload.(*toPassSecure).Field)
	// Output: hello world!
}

func Example_msgpack() {
	type toPass struct {
		Insecure string
		Secure   cryptowrap.Wrapper
	}

	type toPassSecure struct {
		Field string
	}

	key := []byte("0123456789ABCDEF")

	srcSecure := toPassSecure{"hello world!"}

	src := toPass{
		Insecure: "hello",
		Secure: cryptowrap.Wrapper{
			Keys:    [][]byte{key},
			Payload: &srcSecure,
		},
	}

	var b bytes.Buffer

	err := codec.NewEncoder(&b, new(codec.MsgpackHandle)).Encode(&src)
	if err != nil {
		panic(err)
	}

	data := b.Bytes()

	var dstSecure toPassSecure

	dst := toPass{
		Secure: cryptowrap.Wrapper{
			Keys:    [][]byte{key},
			Payload: &dstSecure,
		},
	}

	err = codec.NewDecoderBytes(data, new(codec.MsgpackHandle)).Decode(&dst)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", dst.Secure.Payload.(*toPassSecure).Field)
	// Output: hello world!
}

func Example_rsa() {
	type toPass struct {
		Insecure string
		Secure   cryptowrap.WrapperRSA
	}

	type toPassSecure struct {
		Field string
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	srcSecure := toPassSecure{"world!"}

	src := toPass{
		Insecure: "hello",
		Secure: cryptowrap.WrapperRSA{
			EncKey:  &key.PublicKey,
			Payload: &srcSecure,
		},
	}

	data, err := json.Marshal(&src)
	if err != nil {
		panic(err)
	}

	var dstSecure toPassSecure

	dst := toPass{
		Secure: cryptowrap.WrapperRSA{
			DecKeys: []*rsa.PrivateKey{key},
			Payload: &dstSecure,
		},
	}

	err = json.Unmarshal(data, &dst)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", dst.Secure.Payload.(*toPassSecure).Field)
	// Output: world!
}
