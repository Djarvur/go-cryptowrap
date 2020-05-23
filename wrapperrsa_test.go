package cryptowrap_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"reflect"
	"sync"
	"testing"

	"github.com/Djarvur/cryptowrap"
)

var (
	testKeys2048 = make([]*rsa.PrivateKey, 2)
	testKeys4096 = make([]*rsa.PrivateKey, 2)
	initKeys     sync.Once
)

func testKeysInit() {
	var err error

	for i := 0; i < len(testKeys2048); i++ {
		testKeys2048[i], err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
	}

	for i := 0; i < len(testKeys4096); i++ {
		testKeys4096[i], err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			panic(err)
		}
	}
}

func TestWrapperRSAJSON4096(t *testing.T) {
	testWrapperRSA(t, testKeys4096, false, json.Marshal, json.Unmarshal)
}

func TestWrapperRSAJSON2048Compress(t *testing.T) {
	testWrapperRSA(t, testKeys2048, true, json.Marshal, json.Unmarshal)
}

func TestWrapperRSAJSON4096Compress(t *testing.T) {
	testWrapperRSA(t, testKeys4096, true, json.Marshal, json.Unmarshal)
}

func TestWrapperRSAGob4096(t *testing.T) {
	testWrapperRSA(t, testKeys4096, false, gobMarshal, gobUnmarshal)
}

func TestWrapperRSAGob4096Compress(t *testing.T) {
	testWrapperRSA(t, testKeys4096, true, gobMarshal, gobUnmarshal)
}

func TestWrapperRSAMsgp2048(t *testing.T) {
	testWrapperRSA(t, testKeys2048, false, binMarshal, binUnmarshal)
}

func TestWrapperRSAMsgp4096(t *testing.T) {
	testWrapperRSA(t, testKeys4096, false, binMarshal, binUnmarshal)
}

func TestWrapperRSAMsgp2048Compress(t *testing.T) {
	testWrapperRSA(t, testKeys2048, true, binMarshal, binUnmarshal)
}

func TestWrapperRSAMsgp4096Compress(t *testing.T) {
	testWrapperRSA(t, testKeys4096, true, binMarshal, binUnmarshal)
}

func testWrapperRSA(
	t *testing.T,
	keys []*rsa.PrivateKey,
	compress bool,
	marshaler func(interface{}) ([]byte, error),
	unmarshaler func([]byte, interface{}) error,
) {
	initKeys.Do(testKeysInit)

	label := []byte("test label")

	orig := TestData{
		Field1: "Field1",
		Field2: "Field2",
		Field3: "                                                  ",
	}

	src := cryptowrap.WrapperRSA{
		EncKey:   &keys[len(keys)-1].PublicKey,
		Label:    label,
		Payload:  &orig,
		Compress: compress,
	}

	data, err := marshaler(&src)
	if err != nil {
		t.Error(err)
	}

	dst := cryptowrap.WrapperRSA{
		DecKeys: keys,
		Label:   label,
		Payload: &TestData{},
	}

	err = unmarshaler(data, &dst)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(&orig, dst.Payload) {
		t.Error("decrypted is not equal to original")
	}

	dst = cryptowrap.WrapperRSA{
		DecKeys: []*rsa.PrivateKey{keys[1], keys[0]},
		Label:   label,
		Payload: &TestData{},
	}

	err = unmarshaler(data, &dst)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(&orig, dst.Payload) {
		t.Error("decrypted is not equal to original")
	}

	dst = cryptowrap.WrapperRSA{
		DecKeys: keys,
		Label:   label,
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

func TestWrapperRSAJSONNegative(t *testing.T) {
	testWrapperRSANegative(t, json.Marshal, json.Unmarshal)
}

func TestWrapperRSAGobNegative(t *testing.T) {
	testWrapperRSANegative(t, gobMarshal, gobUnmarshal)
}

func TestWrapperRSAMsgpNegative(t *testing.T) {
	testWrapperRSANegative(t, binMarshal, binUnmarshal)
}

func testWrapperRSANegative(
	t *testing.T,
	marshaler func(interface{}) ([]byte, error),
	unmarshaler func([]byte, interface{}) error,
) {
	initKeys.Do(testKeysInit)

	keys := testKeys4096

	orig := TestData{
		Field1: "Field1",
		Field2: "Field2",
		Field3: "                                                  ",
	}

	src := cryptowrap.WrapperRSA{
		EncKey:  &keys[1].PublicKey,
		Payload: &orig,
	}

	data, err := marshaler(&src)
	if err != nil {
		t.Error(err)
	}

	err = unmarshaler(data, &cryptowrap.WrapperRSA{DecKeys: keys[:1]})
	if err == nil {
		t.Error("decrypted undecryptable")
	}

	err = unmarshaler(data, &cryptowrap.WrapperRSA{Payload: &TestData{}})
	if err == nil {
		t.Error("decrypted undecryptable")
	}

	badKey := []*rsa.PrivateKey{&rsa.PrivateKey{}}

	err = unmarshaler(data, &cryptowrap.WrapperRSA{DecKeys: badKey})
	if err == nil {
		t.Error("decrypted undecryptable")
	}

	_, err = marshaler(&cryptowrap.WrapperRSA{EncKey: &badKey[0].PublicKey, Payload: &orig})
	if err == nil {
		t.Error("encrypted unencryptable")
	}

	data[len(data)/2] = ^data[len(data)/2]

	err = unmarshaler(
		data,
		&cryptowrap.WrapperRSA{
			DecKeys: keys,
		},
	)
	if err == nil {
		t.Error("decrypted undecryptable")
	}

	label := []byte("test label")

	src = cryptowrap.WrapperRSA{
		EncKey:  &keys[1].PublicKey,
		Label:   label,
		Payload: &orig,
	}

	data, err = marshaler(&src)
	if err != nil {
		t.Error(err)
	}

	err = unmarshaler(data, &cryptowrap.WrapperRSA{DecKeys: keys, Payload: &orig, Label: label})
	if err != nil {
		t.Error("undecrypted decryptable")
	}

	err = unmarshaler(data, &cryptowrap.WrapperRSA{DecKeys: keys, Payload: &orig})
	if err == nil {
		t.Error("decrypted undecryptable")
	}

	err = unmarshaler(data, &cryptowrap.WrapperRSA{DecKeys: keys, Payload: &orig, Label: []byte("test label!")})
	if err == nil {
		t.Error("decrypted undecryptable")
	}
}
