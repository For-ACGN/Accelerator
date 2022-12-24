package accelerator

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"github.com/pkg/errors"
)

// -----------------------------------------authentication-----------------------------------------

// Client side send authentication request.
//
// +------------------+--------------------+-------------+
// | SHA256(password) |  random data size  | random data |
// +------------------+--------------------+-------------+
// |     32 bytes     | uint16(big endian) |     var     |
// +------------------+--------------------+-------------+
//
// If authenticate successfully, Server side will send response,
// otherwise Server will read data until connection reach the
// deadline or client side close the connection.
//
// +----------+--------------------+-------------+
// | response |  random data size  | random data |
// +----------+--------------------+-------------+
// |  1 byte  | uint16(big endian) |     var     |
// +----------+--------------------+-------------+
//
// Server response field is always be authOK.
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
// If server is restarted, server will send error about invalid token,
// then the client will log in again automatically.
// If the new connection reach the server side maximum connection pool
// size, server will send error about full.
//
// =========[client request] <------> [server response]===========
//
// Log in
// +---------+-------------+          +----------+---------------+
// | command | random data |          | response | session token |
// +---------+-------------+          +----------+---------------+
// |  byte   |  16 bytes   |          |   byte   |   32 bytes    |
// +---------+-------------+          +----------+---------------+
//
// Log off
// +---------+---------------+        +----------+
// | command | session token |        | response |
// +---------+---------------+        +----------+
// |  byte   |   32 bytes    |        |   byte   |
// +---------+---------------+        +----------+
//
// Transport
// +---------+---------------+        +----------+----------------------+
// | command | session token |        | response | [max conn pool size] |
// +---------+---------------+        +----------+----------------------+
// |  byte   |   32 bytes    |        |   byte   |  uint16(big endian)  |
// +---------+---------------+        +----------+----------------------+
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

	transportOK  = 0x10
	invalidToken = 0x11
	fullConnPool = 0x12
)

type sessionToken = [tokenSize]byte

var emptySessionToken = sessionToken{}

// -------------------------------------------transport--------------------------------------------

// frame structure
//
// +--------------------+------------+
// |  frame data size   | frame data |
// +--------------------+------------+
// | uint16(big endian) |     var    |
// +--------------------+------------+
const (
	maxFrameSize    = 48 * 1024 // 48 KiB
	frameHeaderSize = 2         // uint16
)

type frame struct {
	header []byte
	buf    *bytes.Buffer
}

func newFrame() *frame {
	header := make([]byte, frameHeaderSize)
	buf := bytes.NewBuffer(nil)
	buf.Grow(frameHeaderSize + 1500) // MTU
	return &frame{
		header: header,
		buf:    buf,
	}
}

func (f *frame) WriteHeader(size int) {
	binary.BigEndian.PutUint16(f.header, uint16(size))
	f.buf.Write(f.header)
}

func (f *frame) WriteData(b []byte) {
	f.buf.Write(b)
}

func (f *frame) Data() []byte {
	return f.buf.Bytes()[frameHeaderSize:]
}

func (f *frame) Bytes() []byte {
	return f.buf.Bytes()
}

func (f *frame) Reset() {
	f.buf.Reset()
}
