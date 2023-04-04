package accelerator

import (
	"bytes"
	"errors"
	"io"
)

// cfhWriter and cfhReader are used to compress frame
// header data like Ethernet, IPv4, IPv4, TCP and UDP.
//
// Usually, these data only change a small portion
// throughout the entire context.
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
//
// The threshold is used to quickly detect the need for a new dictionary
const (
	cfhMaxDataSize = 255

	// IPv4(total length, checksum) + UDP(length, checksum)
	defaultThreshold = 4 + 4

	cfhCMDAddDict = 1 + iota
	cfhCMDData
	cfhCMDDelDict
)

type cfhWriter struct {
	w    io.Writer
	dict [][]byte
	th   uint8
	buf  bytes.Buffer
}

func newCFHWriter(w io.Writer) io.Writer {
	return newCFHWriterWithArgs(w, 256, 0)
}

func newCFHWriterWithArgs(w io.Writer, size, threshold uint8) io.Writer {
	if threshold == 0 {
		threshold = defaultThreshold
	}
	return &cfhWriter{
		w:    w,
		dict: make([][]byte, size),
		th:   threshold,
	}
}

func (w *cfhWriter) Write(b []byte) (int, error) {
	if len(b) > cfhMaxDataSize {
		return 0, errors.New("write too large data")
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

func (w *cfhWriter) searchDict(frame []byte) (uint8, bool) {
	size := len(frame)
	switch {
	case size == 14+20+20: // Ethernet + IPv4 + TCP
		return w.fastSearchDictEthIPv4TCP(frame)
	case size == 14+20+8: // Ethernet + IPv4 + UDP
		return w.fastSearchDictEthIPv4UDP(frame)
	case size == 14+40+20: // Ethernet + IPv6 + TCP
		return w.fastSearchDictEthIPv6TCP(frame)
	case size == 14+40+8: // Ethernet + IPv6 + UDP
		return w.fastSearchDictEthIPv6UDP(frame)
	}
	// compare each byte

}

func (w *cfhWriter) fastSearchDictEthIPv4TCP(frame []byte) (uint8, bool) {
	var dict []byte
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], frame[:6+6]) {
			continue
		}
		// IPv4 src/dst address, TCP/UDP src/dst port
		if !bytes.Equal(dict[26:26+4+4+2+2], frame[26:26+4+4+2+2]) {
			continue
		}
		return uint8(i), true
	}
	return 0, false
}

func (w *cfhWriter) fastSearchDictEthIPv4UDP(frame []byte) (uint8, bool) {
	var dict []byte
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], frame[:6+6]) {
			continue
		}
		// IPv4 src/dst address, UDP src/dst port
		if !bytes.Equal(dict[26:26+4+4+2+2], frame[26:26+4+4+2+2]) {
			continue
		}
		return uint8(i), true
	}
	return 0, false
}

func (w *cfhWriter) fastSearchDictEthIPv6TCP(frame []byte) (uint8, bool) {

}

func (w *cfhWriter) fastSearchDictEthIPv6UDP(frame []byte) (uint8, bool) {

}

func (w *cfhWriter) addNewDict(frame []byte) {
	dict := make([]byte, len(frame))
	copy(dict, frame)
	for i := len(w.dict) - 1; i > 0; i-- {
		w.dict[i] = w.dict[i-1]
	}
	w.dict[0] = dict
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
	if len(b) > cfhMaxDataSize {
		return 0, errors.New("read with too large buffer")
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
