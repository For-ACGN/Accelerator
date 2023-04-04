package accelerator

import (
	"bytes"
	"errors"
	"io"
)

// cfhWriter and cfhReader are used to compress frame
// header data like Ethernet, IPv4, IPv4, TCP and UDP.
//
// The data structure is operation + data
//
// 1. add new dictionary
// The new dictionary will be the top.
//
// +---------+-----------------+-----------------+
// | command | dictionary size | dictionary data |
// +---------+-----------------+-----------------+
// |  byte   |      uint8      |    var bytes    |
// +---------+-----------------+-----------------+
//
// 2. write changed data with existed dictionary
//
// +---------+------------------+-------------+-----------+
// | command | dictionary index | data number |   data    |
// +---------+------------------+-------------+-----------+
// |  byte   |      uint8       |    uint8    | var bytes |
// +---------+------------------+-------------+-----------+
//
// changed data structure
// index means changed data offset, data is the new byte
//
// +-------+------+
// | index | data |
// +-------+------+
// | uint8 | byte |
// +-------+------+
//
// 3. delete dictionary
// When the dictionary pool is full, remove the oldest one.
//
// +---------+-------+
// | command | index |
// +---------+-------+
// |  byte   | uint8 |
// +---------+-------+
const (
	cfhCMDAddDict = 1 + iota
	cfgCMDData
	cfhCMDDelDict
)

type cfhWriter struct {
	w    io.Writer
	dict []byte
	buf  bytes.Buffer
}

func newCFHWriter(w io.Writer) io.Writer {
	return &cfhWriter{w: w}
}

func (w *cfhWriter) Write(b []byte) (int, error) {
	if len(b) > 255 {
		return 0, errors.New("too large buffer")
	}
	if w.dict == nil {
		w.dict = make([]byte, len(b))
		copy(w.dict, b)
		_, err := w.w.Write([]byte{byte(len(b))})
		if err != nil {
			return 0, err
		}
		_, err = w.w.Write(w.dict)
		if err != nil {
			return 0, err
		}
		return len(w.dict), nil
	}
	w.buf.Reset()
	// compare the new data with the latest template
	for i := 0; i < len(w.dict); i++ {
		if w.dict[i] == b[i] {
			continue
		}
		w.buf.WriteByte(byte(i))
		w.buf.WriteByte(b[i])
		// update template
		w.dict[i] = b[i]
	}
	// write changed data number
	_, err := w.w.Write([]byte{byte(w.buf.Len() / 2)})
	if err != nil {
		return 0, err
	}
	// write changed data
	_, err = w.w.Write(w.buf.Bytes())
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

type cfhReader struct {
	r    io.Reader
	dict []byte
	buf  []byte
}

func newCFHReader(r io.Reader) io.Reader {
	return &cfhReader{
		r:   r,
		buf: make([]byte, 2),
	}
}

func (r *cfhReader) Read(b []byte) (int, error) {
	if len(b) > 255 {
		return 0, errors.New("too large buffer")
	}
	if r.dict == nil {
		size := make([]byte, 1)
		_, err := io.ReadFull(r.r, size)
		if err != nil {
			return 0, err
		}
		r.dict = make([]byte, size[0])
		_, err = io.ReadFull(r.r, r.dict)
		if err != nil {
			return 0, err
		}
		copy(b, r.dict)
		return len(b), nil
	}
	// read changed data number
	_, err := io.ReadFull(r.r, r.buf[:1])
	if err != nil {
		return 0, err
	}
	num := int(r.buf[0])
	for i := 0; i < num; i++ {
		_, err = io.ReadFull(r.r, r.buf)
		if err != nil {
			return 0, err
		}
		r.dict[r.buf[0]] = r.buf[1]
	}
	copy(b, r.dict)
	return len(b), nil
}
