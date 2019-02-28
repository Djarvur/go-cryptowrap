package cryptowrap

import "crypto/rand"

// RandBytes just gets specified number of bytes from crypto/rand
func RandBytes(keyLen int) ([]byte, error) {
	buf := make([]byte, keyLen)

	_, err := rand.Read(buf)

	return buf, err
}
