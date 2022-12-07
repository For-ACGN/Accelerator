package accelerator

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"github.com/pkg/errors"
)

// -----------------------------------------authentication-----------------------------------------
//
// Client side send authentication request.
//
// +------------------+--------------------------+-------------+
// | SHA256(password) | random data size(uint16) | random data |
// +------------------+--------------------------+-------------+
// |     32 bytes     |         2 bytes          |     var     |
// +------------------+--------------------------+-------------+
//
// If authenticate successfully, Server side will send response,
// otherwise Server will read data until it reach 65536 bytes
// or client side close connection.
//
// +----------+--------------------------+-------------+
// | response | random data size(uint16) | random data |
// +----------+--------------------------+-------------+
// |  1 byte  |         2 bytes          |     var     |
// +----------+--------------------------+-------------+
//
// response field is always be 0x01.

func buildAuthRequest(hash []byte) ([]byte, error) {
	padding, err := generateRandomData()
	if err != nil {
		return nil, err
	}
	req := make([]byte, 0, sha256.Size+len(padding))
	req = append(req, hash...)
	req = append(req, padding...)
	return req, nil
}

func buildAuthResponse() ([]byte, error) {
	padding, err := generateRandomData()
	if err != nil {
		return nil, err
	}
	resp := make([]byte, 0, 1+len(padding))
	resp = append(resp, 0x01)
	resp = append(resp, padding...)
	return resp, nil
}

func generateRandomData() ([]byte, error) {
	sizeBuf := make([]byte, 2)
	_, err := rand.Read(sizeBuf)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	size := binary.BigEndian.Uint16(sizeBuf)
	padding := make([]byte, size)
	_, err = rand.Read(padding)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return append(sizeBuf, padding...), nil
}

// -------------------------------------------transport--------------------------------------------
//
// frame packet structure
//
// +--------------+-------------+
// | size(uint16) |  frame data |
// +--------------+-------------+
// |   2 bytes    |     var     |
// +--------------+-------------+

const (
	maxPacketSize   = 32 * 1024 // 32 KiB (size+data)
	frameHeaderSize = 2         // uint16, use big endian
)

type packet struct {
	buf  []byte
	size int
}

func newPacket() *packet {
	return &packet{
		buf:  make([]byte, maxPacketSize),
		size: 0,
	}
}
