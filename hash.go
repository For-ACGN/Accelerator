package accelerator

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/pkg/errors"
)

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
