package accelerator

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"

	"github.com/pkg/errors"
)

// for server map key and network
type mac = [6]byte
type ipv4 = [net.IPv4len]byte
type ipv6 = [net.IPv6len]byte
type port = [2]byte

var broadcast = mac{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

// -----------------------------------------authentication-----------------------------------------

// Client side send authentication request.
//
// +------------------+--------------------------+-------------+
// | SHA256(password) | random data size(uint16) | random data |
// +------------------+--------------------------+-------------+
// |     32 bytes     |         2 bytes          |     var     |
// +------------------+--------------------------+-------------+
//
// If authenticate successfully, Server side will send response,
// otherwise Server will read data until connection reach the
// deadline or client side close the connection.
//
// +----------+--------------------------+-------------+
// | response | random data size(uint16) | random data |
// +----------+--------------------------+-------------+
// |  1 byte  |         2 bytes          |     var     |
// +----------+--------------------------+-------------+
//
// response field is always be authOK.
const authOK = 0x01

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
	resp = append(resp, authOK)
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

// --------------------------------------------command---------------------------------------------

// When the Client send cmdLogin, Server will create a new connection
// pool for it, then return a session token to client for transport
// and log off. Usually, Client will send cmdLogoff before it closed,
// then Server will remove the connection pool (all connections will
// be closed) about it.
//
// Use extra session token is used to prevent other users force
// log off current user.
//
// When the Client send cmdTransport, Server will add new connection
// to the exists connection pool.
//
// =========[client request] <------> [server response]===========
//
// Login
// +---------+-------------+          +----------+---------------+
// | command | random data |          | response | session token |
// +---------+-------------+          +----------+---------------+
// |  byte   |  16 bytes   |          |   byte   |   32 bytes    |
// +---------+-------------+          +----------+---------------+
//
// Logoff
// +---------+---------------+        +----------+
// | command | session token |        | response |
// +---------+---------------+        +----------+
// |  byte   |   32 bytes    |        |   byte   |
// +---------+---------------+        +----------+
//
// Transport
// +---------+---------------+        +----------+
// | command | session token |        | response |
// +---------+---------------+        +----------+
// |  byte   |   32 bytes    |        |   byte   |
// +---------+---------------+        +----------+
const (
	cmdLogin = iota
	cmdLogoff
	cmdTransport
)

const (
	cmdSize   = 1
	obfSize   = 16
	tokenSize = 32

	loginOK  = 0x01
	logoffOK = 0x02
	transOK  = 0x03
)

type sessionToken = [tokenSize]byte

var emptySessionToken = sessionToken{}

// -------------------------------------------transport--------------------------------------------

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
	size uint16
}

func newPacket() *packet {
	return &packet{
		buf:  make([]byte, maxPacketSize),
		size: 0,
	}
}
