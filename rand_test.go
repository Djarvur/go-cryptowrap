package cryptowrap_test

import "crypto/rand"

func randBytes(l int) []byte {
	buf := make([]byte, l)

	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}

	return buf
}
