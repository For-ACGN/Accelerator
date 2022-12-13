package accelerator

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

// GeneratePasswordHash is used to generate password hash.
func GeneratePasswordHash(password []byte) string {
	key := pbkdf2.Key(password, []byte("acc"), 8192, sha256.Size, sha256.New)
	return hex.EncodeToString(key)
}

func decodePasswordHash(hash string) ([]byte, error) {
	passHash, err := hex.DecodeString(hash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode password hash")
	}
	if len(passHash) != sha256.Size {
		return nil, errors.Wrap(err, "invalid password hash size")
	}
	return passHash, nil
}
