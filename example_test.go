package cryptowrap_test

import (
	"encoding/json"
	"fmt"

	"github.com/Djarvur/cryptowrap"
)

func Example_direct() {
	key, err := cryptowrap.RandBytes(16)
	if err != nil {
		panic(err)
	}

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

	key, err := cryptowrap.RandBytes(16)
	if err != nil {
		panic(err)
	}

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
