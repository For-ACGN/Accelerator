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
// 3. repeat last frame header data
//
// +---------+
// | command |
// +---------+
// |  byte   |
// +---------+
//
// 4. repeat previous frame header data
//
// +---------+------------------+
// | command | dictionary index |
// +---------+------------------+
// |  byte   |      uint8       |
// +---------+------------------+
const cfhMaxDataSize = 255

const (
	cfhCMDAddDict = 1 + iota
	cfhCMDData
	cfhCMDLast
	cfhCMDPrev
)

type cfhWriter struct {
	w    io.Writer
	dict [][]byte
	last bytes.Buffer
	chg  bytes.Buffer
	buf  bytes.Buffer
}

func newCFHWriter(w io.Writer) io.Writer {
	return newCFHWriterWithSize(w, 256)
}

func newCFHWriterWithSize(w io.Writer, size uint8) io.Writer {
	return &cfhWriter{
		w:    w,
		dict: make([][]byte, size),
	}
}

func (w *cfhWriter) Write(b []byte) (int, error) {
	n := len(b)
	if n > cfhMaxDataSize {
		return 0, errors.New("write too large data")
	}
	w.buf.Reset()
	// check data is as same as the last
	if bytes.Equal(w.last.Bytes(), b) {
		w.buf.WriteByte(cfhCMDLast)
		_, err := w.w.Write(w.buf.Bytes())
		if err != nil {
			return 0, err
		}
		return n, nil
	}
	// search the dictionary
	idx := w.searchDict(b)
	if idx == -1 {
		w.addDict(b)
		w.updateLast(b)
		w.buf.WriteByte(cfhCMDAddDict)
		w.buf.WriteByte(byte(n))
		w.buf.Write(b)
		_, err := w.w.Write(w.buf.Bytes())
		if err != nil {
			return 0, err
		}
		return n, nil
	}
	// compare the new data with the dictionary
	dict := w.dict[idx]
	for i := 0; i < n; i++ {
		if dict[i] == b[i] {
			continue
		}
		w.chg.WriteByte(byte(i))
		w.chg.WriteByte(b[i])
		// update dictionary data
		dict[i] = b[i]
	}
	if w.chg.Len() == 0 {
		w.buf.WriteByte(cfhCMDPrev)
		w.buf.WriteByte(byte(idx))
	} else {
		w.buf.WriteByte(cfhCMDData)
		w.buf.WriteByte(byte(idx))
		w.buf.WriteByte(byte(w.chg.Len() / 2))
		w.buf.Write(w.chg.Bytes())
		w.chg.Reset()
	}
	// move the dictionary to the top
	w.moveDict(idx)
	w.updateLast(b)
	// write the actual changed data
	_, err := w.w.Write(w.buf.Bytes())
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (w *cfhWriter) searchDict(frame []byte) int {
	size := len(frame)
	switch {
	case size == 14+20+20:
		return w.fastSearchDictEthernetIPv4TCP(frame)
	case size == 14+20+8:
		return w.fastSearchDictEthernetIPv4UDP(frame)
	case size == 14+40+20:
		return w.fastSearchDictEthernetIPv6TCP(frame)
	case size == 14+40+8:
		return w.fastSearchDictEthernetIPv6UDP(frame)
	default:
		return w.slowSearchDict(frame)
	}
}

func (w *cfhWriter) fastSearchDictEthernetIPv4TCP(frame []byte) int {
	const offset = 14 + (20 - 4*2)
	var dict []byte
	frameP1 := frame[:6+6]
	frameP2 := frame[offset : offset+4+4+2+2]
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(frame) {
			continue
		}
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], frameP1) {
			continue
		}
		// IPv4 src/dst address, TCP/UDP src/dst port
		if !bytes.Equal(dict[offset:offset+4+4+2+2], frameP2) {
			continue
		}
		return i
	}
	return -1
}

func (w *cfhWriter) fastSearchDictEthernetIPv4UDP(frame []byte) int {
	const offset = 14 + (20 - 4*2)
	var dict []byte
	frameP1 := frame[:6+6]
	frameP2 := frame[offset : offset+4+4+2+2]
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(frame) {
			continue
		}
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], frameP1) {
			continue
		}
		// IPv4 src/dst address, UDP src/dst port
		if !bytes.Equal(dict[offset:offset+4+4+2+2], frameP2) {
			continue
		}
		return i
	}
	return -1
}

func (w *cfhWriter) fastSearchDictEthernetIPv6TCP(frame []byte) int {
	const offset = 14 + (40 - 16*2)
	var dict []byte
	frameP1 := frame[:6+6]
	frameP2 := frame[offset : offset+16+16+2+2]
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(frame) {
			continue
		}
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], frameP1) {
			continue
		}
		// IPv6 src/dst address, TCP/UDP src/dst port
		if !bytes.Equal(dict[offset:offset+16+16+2+2], frameP2) {
			continue
		}
		return i
	}
	return -1
}

func (w *cfhWriter) fastSearchDictEthernetIPv6UDP(frame []byte) int {
	const offset = 14 + (40 - 16*2)
	var dict []byte
	frameP1 := frame[:6+6]
	frameP2 := frame[offset : offset+16+16+2+2]
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(frame) {
			continue
		}
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], frameP1) {
			continue
		}
		// IPv6 src/dst address, UDP src/dst port
		if !bytes.Equal(dict[offset:offset+16+16+2+2], frameP2) {
			continue
		}
		return i
	}
	return -1
}

func (w *cfhWriter) slowSearchDict(frame []byte) int {
	var (
		dict []byte
		diff int
	)
	minDiff := cfhMaxDataSize
	maxDiff := len(frame) / 4
	dictIdx := -1
next:
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(frame) {
			continue
		}
		diff = 0
		for j := 0; j < len(dict); j++ {
			if dict[j] == frame[j] {
				continue
			}
			diff++
			if diff > maxDiff {
				continue next
			}
		}
		if diff < minDiff {
			minDiff = diff
			dictIdx = i
		}
	}
	return dictIdx
}

func (w *cfhWriter) addDict(frame []byte) {
	// remove the oldest dictionary
	for i := len(w.dict) - 1; i > 0; i-- {
		w.dict[i] = w.dict[i-1]
	}
	dict := make([]byte, len(frame))
	copy(dict, frame)
	w.dict[0] = dict
}

func (w *cfhWriter) moveDict(idx int) {
	dict := w.dict[idx]
	for i := idx; i > 0; i-- {
		w.dict[i] = w.dict[i-1]
	}
	w.dict[0] = dict
}

func (w *cfhWriter) updateLast(frame []byte) {
	w.last.Reset()
	w.last.Write(frame)
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
