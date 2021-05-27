package cryptowrap_test

import (
	"crypto/rsa"
	"encoding/gob"
	"encoding/json"
	"testing"

	"github.com/Djarvur/cryptowrap"
)

func BenchmarkWrapperRSAJSON2048(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys2048, false, json.Marshal, json.Unmarshal)
}

func BenchmarkWrapperRSAJSON4096(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys4096, false, json.Marshal, json.Unmarshal)
}

func BenchmarkWrapperRSAJSON2048Compress(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys2048, true, json.Marshal, json.Unmarshal)
}

func BenchmarkWrapperRSAJSON4096Compress(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys4096, true, json.Marshal, json.Unmarshal)
}

func BenchmarkWrapperRSAGob4096(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys4096, false, gobMarshal, gobUnmarshal)
}

func BenchmarkWrapperRSAGob4096Compress(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys4096, true, gobMarshal, gobUnmarshal)
}

func BenchmarkWrapperRSAMsgp2048(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys2048, false, binMarshal, binUnmarshal)
}

func BenchmarkWrapperRSAMsgp4096(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys4096, false, binMarshal, binUnmarshal)
}

func BenchmarkWrapperRSAMsgp2048Compress(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys2048, true, binMarshal, binUnmarshal)
}

func BenchmarkWrapperRSAMsgp4096Compress(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys4096, true, binMarshal, binUnmarshal)
}

func BenchmarkWrapperRSACBOR2048(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys2048, false, cborMarshal, cborUnmarshal)
}

func BenchmarkWrapperRSACBOR4096(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys4096, false, cborMarshal, cborUnmarshal)
}

func BenchmarkWrapperRSACBOR2048Compress(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys2048, true, cborMarshal, cborUnmarshal)
}

func BenchmarkWrapperRSACBOR4096Compress(b *testing.B) {
	benchmarkWrapperRSA(b, testKeys4096, true, cborMarshal, cborUnmarshal)
}

func benchmarkWrapperRSA(
	b *testing.B,
	keys []*rsa.PrivateKey,
	compress bool,
	marshaler func(interface{}) ([]byte, error),
	unmarshaler func([]byte, interface{}) error,
) {
	b.StopTimer()

	initKeys.Do(testKeysInit)

	type toPass struct {
		Insecure string
		Secure   cryptowrap.WrapperRSA
	}

	type toPassSecureRSA struct {
		Field string
	}

	gob.Register(&toPassSecureRSA{})

	key := keys[0]

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		srcSecure := toPassSecureRSA{"world!"}

		src := toPass{
			Insecure: "hello",
			Secure: cryptowrap.WrapperRSA{
				EncKey:   &key.PublicKey,
				Payload:  &srcSecure,
				Compress: compress,
			},
		}

		data, err := marshaler(&src)
		if err != nil {
			panic(err)
		}

		var dstSecure toPassSecureRSA

		dst := toPass{
			Secure: cryptowrap.WrapperRSA{
				DecKeys: []*rsa.PrivateKey{key},
				Payload: &dstSecure,
			},
		}

		err = unmarshaler(data, &dst)
		if err != nil {
			panic(err)
		}
	}
}
