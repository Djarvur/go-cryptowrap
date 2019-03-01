package cryptowrap_test

import (
	"encoding/json"
	"testing"

	"github.com/Djarvur/cryptowrap"
)

func BenchmarkRaw(b *testing.B) {
	type rawWrapper struct {
		Payload interface{}
	}

	type toPass struct {
		Insecure string
		Secure   rawWrapper
	}

	type toPassSecure struct {
		Field string
	}

	for i := 0; i < b.N; i++ {
		srcSecure := toPassSecure{"world!"}

		src := toPass{
			Insecure: "hello",
			Secure: rawWrapper{
				Payload: &srcSecure,
			},
		}

		data, err := json.Marshal(&src)
		if err != nil {
			panic(err)
		}

		var dstSecure toPassSecure

		dst := toPass{
			Secure: rawWrapper{
				Payload: &dstSecure,
			},
		}

		err = json.Unmarshal(data, &dst)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkWrapper128(b *testing.B) {
	benchmarkWrapper(b, 16, false)
}

func BenchmarkWrapper256(b *testing.B) {
	benchmarkWrapper(b, 32, false)
}

func BenchmarkWrapper128Compress(b *testing.B) {
	benchmarkWrapper(b, 16, true)
}

func BenchmarkWrapper256Compress(b *testing.B) {
	benchmarkWrapper(b, 32, true)
}

func benchmarkWrapper(b *testing.B, keyLen int, compress bool) {
	b.StopTimer()

	type toPass struct {
		Insecure string
		Secure   cryptowrap.Wrapper
	}

	type toPassSecure struct {
		Field string
	}

	key := randBytes(keyLen)

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		srcSecure := toPassSecure{"world!"}

		src := toPass{
			Insecure: "hello",
			Secure: cryptowrap.Wrapper{
				Keys:    [][]byte{key},
				Payload: &srcSecure,
				Compress: compress,
			},
		}

		data, err := json.Marshal(&src)
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

		err = json.Unmarshal(data, &dst)
		if err != nil {
			panic(err)
		}
	}
}
