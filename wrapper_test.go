package cryptowrap_test

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Djarvur/cryptowrap"
	"github.com/ugorji/go/codec"
)

type TestData struct {
	Field1 string
	Field2 string
	Field3 string
}

func init() {
	gob.Register(&TestData{})
}

func TestWrapperJSON128(t *testing.T) {
	testWrapper(t, 16, false, json.Marshal, json.Unmarshal)
}

func TestWrapperJSON256(t *testing.T) {
	testWrapper(t, 32, false, json.Marshal, json.Unmarshal)
}

func TestWrapperJSON128Compress(t *testing.T) {
	testWrapper(t, 16, true, json.Marshal, json.Unmarshal)
}

func TestWrapperJSON256Compress(t *testing.T) {
	testWrapper(t, 32, true, json.Marshal, json.Unmarshal)
}

func TestWrapperGob128(t *testing.T) {
	testWrapper(t, 16, false, gobMarshal, gobUnmarshal)
}

func TestWrapperGob256(t *testing.T) {
	testWrapper(t, 32, false, gobMarshal, gobUnmarshal)
}

func TestWrapperGob128Compress(t *testing.T) {
	testWrapper(t, 16, true, gobMarshal, gobUnmarshal)
}

func TestWrapperGob256Compress(t *testing.T) {
	testWrapper(t, 32, true, gobMarshal, gobUnmarshal)
}

func TestWrapperMsgp128(t *testing.T) {
	testWrapper(t, 16, false, binMarshal, binUnmarshal)
}

func TestWrapperMsgp256(t *testing.T) {
	testWrapper(t, 32, false, binMarshal, binUnmarshal)
}

func TestWrapperMsgp128Compress(t *testing.T) {
	testWrapper(t, 16, true, binMarshal, binUnmarshal)
}

func TestWrapperMsgp256Compress(t *testing.T) {
	testWrapper(t, 32, true, binMarshal, binUnmarshal)
}

func testWrapper(
	t *testing.T,
	keyLen int,
	compress bool,
	marshaler func(interface{}) ([]byte, error),
	unmarshaler func([]byte, interface{}) error,
) {
	keys := [][]byte{
		randBytes(keyLen),
		randBytes(keyLen),
	}

	orig := TestData{
		Field1: "Field1",
		Field2: "Field2",
		Field3: "                                                  ",
	}

	src := cryptowrap.Wrapper{
		Keys:     keys[1:],
		Payload:  &orig,
		Compress: compress,
	}

	data, err := marshaler(&src)
	if err != nil {
		t.Error(err)
	}

	dst := cryptowrap.Wrapper{
		Keys:    keys[1:],
		Payload: &TestData{},
	}

	err = unmarshaler(data, &dst)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(&orig, dst.Payload) {
		t.Error("decrypted is not equal to original")
	}

	dst = cryptowrap.Wrapper{
		Keys:    keys,
		Payload: &TestData{},
	}

	err = unmarshaler(data, &dst)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(&orig, dst.Payload) {
		t.Error("decrypted is not equal to original")
	}

	dst = cryptowrap.Wrapper{
		Keys:    [][]byte{keys[1], keys[0]},
		Payload: &TestData{},
	}

	err = unmarshaler(data, &dst)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(&orig, dst.Payload) {
		t.Error("decrypted is not equal to original")
	}
}

func TestWrapperJSONNegative(t *testing.T) {
	testWrapperNegative(t, json.Marshal, json.Unmarshal)
}

func TestWrapperGobNegative(t *testing.T) {
	testWrapperNegative(t, gobMarshal, gobUnmarshal)
}

func TestWrapperMsgpNegative(t *testing.T) {
	testWrapperNegative(t, binMarshal, binUnmarshal)
}

func testWrapperNegative(
	t *testing.T,
	marshaler func(interface{}) ([]byte, error),
	unmarshaler func([]byte, interface{}) error,
) {
	keys := [][]byte{
		randBytes(16),
		randBytes(16),
	}

	orig := TestData{
		Field1: "Field1",
		Field2: "Field2",
		Field3: "                                                  ",
	}

	src := cryptowrap.Wrapper{
		Keys:    keys[1:],
		Payload: &orig,
	}

	data, err := marshaler(&src)
	if err != nil {
		t.Error(err)
	}

	err = unmarshaler(data, &cryptowrap.Wrapper{Keys: keys[:1]})
	if err == nil {
		t.Error("decrypted undecryptable")
	}

	err = unmarshaler(data, &cryptowrap.Wrapper{Payload: &TestData{}})
	if err == nil {
		t.Error("decrypted undecryptable")
	}

	badKey := [][]byte{randBytes(15)}

	err = unmarshaler(data, &cryptowrap.Wrapper{Keys: badKey})
	if err == nil {
		t.Error("decrypted undecryptable")
	}

	_, err = marshaler(&cryptowrap.Wrapper{Keys: badKey, Payload: &orig})
	if err == nil {
		t.Error("encrypted unencryptable")
	}

	_, err = marshaler(&cryptowrap.Wrapper{Payload: &orig})
	if err == nil {
		t.Error("encrypted unencryptable")
	}

	data[len(data)/2] = 0

	err = unmarshaler(
		data,
		&cryptowrap.Wrapper{
			Keys: keys,
		},
	)
	if err == nil {
		t.Error("decrypted undecryptable")
	}

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
