package sha1

import (
	"crypto/sha1"
)

const (
	BlockSize = sha1.BlockSize
	Size      = sha1.Size
)

type Hasher interface {
	Write(data []byte) (n int, err error)
	Sum() ([Size]byte, error)
	Close()
}

func SHA1(data []byte) (result [Size]byte, err error) {
	hash, err := New()
	if err != nil {
		return result, err
	}
	defer hash.Close()
	if _, err := hash.Write(data); err != nil {
		return result, err
	}
	return hash.Sum()
}
