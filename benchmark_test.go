package cryptowrap_test

import (
	"encoding/gob"
	"encoding/json"
	"testing"

	"github.com/Djarvur/cryptowrap"
)

func BenchmarkRawJSON(b *testing.B) {
	benchmarkRaw(b, json.Marshal, json.Unmarshal)
}

func BenchmarkRawGob(b *testing.B) {
	benchmarkRaw(b, gobMarshal, gobUnmarshal)
}

func BenchmarkRawMsgp(b *testing.B) {
	benchmarkRaw(b, binMarshal, binUnmarshal)
}

func benchmarkRaw(
	b *testing.B,
	marshaler func(interface{}) ([]byte, error),
	unmarshaler func([]byte, interface{}) error,
) {
	type rawWrapper struct {
		Payload interface{}
	}

	type toPass struct {
		Insecure string
		Secure   rawWrapper
	}

	type toPassRaw struct {
		Field string
	}

	gob.Register(&toPassRaw{})

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		srcSecure := toPassRaw{"world!"}

		src := toPass{
			Insecure: "hello",
			Secure: rawWrapper{
				Payload: &srcSecure,
			},
		}

		data, err := marshaler(&src)
		if err != nil {
			panic(err)
		}

		var dstSecure toPassRaw

		dst := toPass{
			Secure: rawWrapper{
				Payload: &dstSecure,
			},
		}

		err = unmarshaler(data, &dst)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkWrapperJSON128(b *testing.B) {
	benchmarkWrapper(b, 16, false, json.Marshal, json.Unmarshal)
}

func BenchmarkWrapperJSON256(b *testing.B) {
	benchmarkWrapper(b, 32, false, json.Marshal, json.Unmarshal)
}

func BenchmarkWrapperJSON128Compress(b *testing.B) {
	benchmarkWrapper(b, 16, true, json.Marshal, json.Unmarshal)
}

func BenchmarkWrapperJSON256Compress(b *testing.B) {
	benchmarkWrapper(b, 32, true, json.Marshal, json.Unmarshal)
}

func BenchmarkWrapperGob128(b *testing.B) {
	benchmarkWrapper(b, 16, false, gobMarshal, gobUnmarshal)
}

func BenchmarkWrapperGob256(b *testing.B) {
	benchmarkWrapper(b, 32, false, gobMarshal, gobUnmarshal)
}

func BenchmarkWrapperGob128Compress(b *testing.B) {
	benchmarkWrapper(b, 16, true, gobMarshal, gobUnmarshal)
}

func BenchmarkWrapperGob256Compress(b *testing.B) {
	benchmarkWrapper(b, 32, true, gobMarshal, gobUnmarshal)
}

func BenchmarkWrapperMsgp128(b *testing.B) {
	benchmarkWrapper(b, 16, false, binMarshal, binUnmarshal)
}

func BenchmarkWrapperMsgp256(b *testing.B) {
	benchmarkWrapper(b, 32, false, binMarshal, binUnmarshal)
}

func BenchmarkWrapperMsgp128Compress(b *testing.B) {
	benchmarkWrapper(b, 16, true, binMarshal, binUnmarshal)
}

func BenchmarkWrapperMsgp256Compress(b *testing.B) {
	benchmarkWrapper(b, 32, true, binMarshal, binUnmarshal)
}

func benchmarkWrapper(
	b *testing.B,
	keyLen int,
	compress bool,
	marshaler func(interface{}) ([]byte, error),
	unmarshaler func([]byte, interface{}) error,
) {
	b.StopTimer()

	type toPass struct {
		Insecure string
		Secure   cryptowrap.Wrapper
	}

	type toPassSecure struct {
		Field string
	}

	gob.Register(&toPassSecure{})

	key := randBytes(keyLen)

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		srcSecure := toPassSecure{"world!"}

		src := toPass{
			Insecure: "hello",
			Secure: cryptowrap.Wrapper{
				Keys:     [][]byte{key},
				Payload:  &srcSecure,
				Compress: compress,
			},
		}

		data, err := marshaler(&src)
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

		err = unmarshaler(data, &dst)
		if err != nil {
			panic(err)
		}
	}
}
