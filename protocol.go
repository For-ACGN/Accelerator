package accelerator

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

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
	var size uint16
	for size < 128 {
		_, err := rand.Read(sizeBuf)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate random data size")
		}
		size = binary.BigEndian.Uint16(sizeBuf)
	}
	padding := make([]byte, size)
	_, err := rand.Read(padding)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate random data")
	}
	return append(sizeBuf, padding...), nil
}

// TODO use it in server and client
func readPaddingRandomData(r io.Reader) error {
	buf := make([]byte, 2)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return errors.Wrap(err, "failed to read random data size")
	}
	size := binary.BigEndian.Uint16(buf)
	_, err = io.CopyN(io.Discard, r, int64(size))
	if err != nil {
		return errors.Wrap(err, "failed to receive padding random data")
	}
	return nil
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
// ============[client request]============        ============[server response]============
//
// --------Log in--------
// +---------+-------------+                       +---------------+-------------+
// | command | random data |                       | session token | random data |
// +---------+-------------+                       +---------------+-------------+
// |  byte   | 2+var bytes |                       |   32 bytes    | 2+var bytes |
// +---------+-------------+                       +---------------+-------------+
//
// # query connection pool size
// +-------------+                                 +--------------------+-------------+
// | random data |                                 | max conn pool size | random data |
// +-------------+                                 +--------------------+-------------+
// | 2+var bytes |                                 | uint16(big endian) | 2+var bytes |
// +-------------+                                 +--------------------+-------------+
//
// # set connection pool size
// +--------------------+-------------+            +----------+-------------+
// |   conn pool size   | random data |            | response | random data |
// +--------------------+-------------+            +----------+-------------+
// | uint16(big endian) | 2+var bytes |            |   byte   | 2+var bytes |
// +--------------------+-------------+            +----------+-------------+
//
// --------Log off--------
// +---------+---------------+-------------+       +----------+-------------+
// | command | session token | random data |       | response | random data |
// +---------+---------------+-------------+       +----------+-------------+
// |  byte   |   32 bytes    | 2+var bytes |       |   byte   | 2+var bytes |
// +---------+---------------+-------------+       +----------+-------------+
//
// --------Transport--------
//
// [client request]
// +---------+---------------+---------+-------------+
// | command | session token | options | random data |
// +---------+---------------+---------+-------------+
// |  byte   |   32 bytes    |   var   | 2+var bytes |
// +---------+---------------+---------+-------------+
//
// # options in client request
// +---------+-----------------------+
// | num opt | compress frame header |
// +---------+-----------------------+
// |  uint8  |          bool         |
// +---------+-----------------------+
//
// [server response]
// +----------+---------+-------------+
// | response | options | random data |
// +----------+---------+-------------+
// |   byte   |   var   | 2+var bytes |
// +----------+---------+-------------+
//
// # options in server response
// +---------+--------------------+
// | num opt | max conn pool size |
// +---------+--------------------+
// |  uint8  | uint16(big endian) |
// +---------+--------------------+
const (
	cmdLogin = 1 + iota
	cmdLogoff
	cmdTransport
)

const (
	cmdSize   = 1
	tokenSize = 32

	loginOK  = 0x01
	logoffOK = 0x02

	transportOK  = 0x10
	invalidToken = 0x11

	enableCFH    = 0x20
	fullConnPool = 0x80
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
	maxFrameSize    = 64*1024 - 1 // 64 KiB
	frameHeaderSize = 2           // uint16
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
