package accelerator

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// cfhWriter and cfhReader are used to compress frame
// header data like Ethernet, IPv4, IPv4, TCP and UDP.
// Usually, these data only change a small portion
// throughout the entire context.
//
// When call Write method, the compressor will compress
// data and write output to the under writer at once.
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
const cfhMaxDataSize = 256

const (
	cfhCMDAddDict = 1 + iota
	cfhCMDData
	cfhCMDLast
	cfhCMDPrev
)

// cfhWriter is used to compress frame header data.
type cfhWriter struct {
	w    io.Writer
	dict [][]byte
	last bytes.Buffer
	chg  bytes.Buffer
	buf  bytes.Buffer
	err  error
}

func newCFHWriter(w io.Writer) io.Writer {
	w, _ = newCFHWriterWithSize(w, 256)
	return w
}

func newCFHWriterWithSize(w io.Writer, size int) (io.Writer, error) {
	if size < 1 {
		return nil, errors.New("dictionary size cannot less than 1")
	}
	if size > 256 {
		return nil, errors.New("dictionary size cannot greater than 256")
	}
	return &cfhWriter{
		w:    w,
		dict: make([][]byte, size),
	}, nil
}

func (w *cfhWriter) Write(b []byte) (int, error) {
	l := len(b)
	if l < 1 {
		return 0, nil
	}
	if l > cfhMaxDataSize {
		return 0, errors.New("write too large data")
	}
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.write(b)
	if err != nil {
		w.err = err
	}
	return n, err
}

func (w *cfhWriter) write(b []byte) (int, error) {
	n := len(b)
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
	idx := w.searchDictionary(b)
	if idx == -1 {
		w.buf.WriteByte(cfhCMDAddDict)
		w.buf.WriteByte(byte(n))
		w.buf.Write(b)
		_, err := w.w.Write(w.buf.Bytes())
		if err != nil {
			return 0, err
		}
		w.addDictionary(b)
		w.updateLast(b)
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
	// write the actual changed data
	_, err := w.w.Write(w.buf.Bytes())
	if err != nil {
		return 0, err
	}
	// move the dictionary to the top
	w.moveDictionary(idx)
	w.updateLast(b)
	return n, nil
}

func (w *cfhWriter) searchDictionary(data []byte) int {
	size := len(data)
	switch {
	case size == 14+20+20:
		return w.fastSearchDictEthernetIPv4TCP(data)
	case size == 14+20+8:
		return w.fastSearchDictEthernetIPv4UDP(data)
	case size == 14+40+20:
		return w.fastSearchDictEthernetIPv6TCP(data)
	case size == 14+40+8:
		return w.fastSearchDictEthernetIPv6UDP(data)
	default:
		return w.slowSearchDict(data)
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

func (w *cfhWriter) slowSearchDict(data []byte) int {
	var (
		dict []byte
		diff int
	)
	minDiff := cfhMaxDataSize
	maxDiff := len(data) / 4
	dictIdx := -1
next:
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(data) {
			continue
		}
		diff = 0
		for j := 0; j < len(dict); j++ {
			if dict[j] == data[j] {
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

func (w *cfhWriter) addDictionary(data []byte) {
	// remove the oldest dictionary
	for i := len(w.dict) - 1; i > 0; i-- {
		w.dict[i] = w.dict[i-1]
	}
	dict := make([]byte, len(data))
	copy(dict, data)
	w.dict[0] = dict
}

func (w *cfhWriter) moveDictionary(idx int) {
	if idx == 0 {
		return
	}
	dict := w.dict[idx]
	for i := idx; i > 0; i-- {
		w.dict[i] = w.dict[i-1]
	}
	w.dict[0] = dict
}

func (w *cfhWriter) updateLast(data []byte) {
	w.last.Reset()
	w.last.Write(data)
}

// cfhReader is used to decompress frame header data.
type cfhReader struct {
	r    io.Reader
	dict [][]byte
	buf  []byte
	chg  []byte
	last bytes.Buffer
	data bytes.Buffer
	err  error
}

func newCFHReader(r io.Reader) io.Reader {
	r, _ = newCFHReaderWithSize(r, 256)
	return r
}

func newCFHReaderWithSize(r io.Reader, size int) (io.Reader, error) {
	if size < 1 {
		return nil, errors.New("dictionary size cannot less than 1")
	}
	if size > 256 {
		return nil, errors.New("dictionary size cannot greater than 256")
	}
	return &cfhReader{
		r:    r,
		dict: make([][]byte, size),
		buf:  make([]byte, 1),
		chg:  make([]byte, 256),
	}, nil
}

func (r *cfhReader) Read(b []byte) (int, error) {
	l := len(b)
	if l < 1 {
		return 0, nil
	}
	if l > cfhMaxDataSize {
		return 0, errors.New("read with too large buffer")
	}
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.read(b)
	if err != nil {
		r.err = err
	}
	return n, err
}

func (r *cfhReader) read(b []byte) (int, error) {
	// read remaining data
	if r.data.Len() != 0 {
		return r.data.Read(b)
	}
	// read command
	_, err := io.ReadFull(r.r, r.buf)
	if err != nil {
		return 0, fmt.Errorf("failed to read decompress command: %s", err)
	}
	switch cmd := r.buf[0]; cmd {
	case cfhCMDAddDict:
		err = r.addDictionary()
	case cfhCMDData:
		err = r.readChangedData()
	case cfhCMDLast:
		r.reuseLastData()
	case cfhCMDPrev:
		err = r.reusePreviousData()
	default:
		return 0, fmt.Errorf("invalid decompress command: %d", cmd)
	}
	if err != nil {
		return 0, err
	}
	return r.data.Read(b)
}

func (r *cfhReader) addDictionary() error {
	// read dictionary size
	_, err := io.ReadFull(r.r, r.buf)
	if err != nil {
		return fmt.Errorf("failed to read dictionary size: %s", err)
	}
	size := int(r.buf[0])
	if size < 1 {
		return errors.New("read empty dictionary")
	}
	// read dictionary data
	dict := make([]byte, size)
	_, err = io.ReadFull(r.r, dict)
	if err != nil {
		return fmt.Errorf("failed to read dictionary data: %s", err)
	}
	// remove the oldest dictionary
	for i := len(r.dict) - 1; i > 0; i-- {
		r.dict[i] = r.dict[i-1]
	}
	r.dict[0] = dict
	r.data.Write(dict)
	// update status
	r.updateLast(dict)
	return nil
}

func (r *cfhReader) readChangedData() error {
	// read dictionary index
	_, err := io.ReadFull(r.r, r.buf)
	if err != nil {
		return fmt.Errorf("failed to read dictionary index: %s", err)
	}
	idx := int(r.buf[0])
	// read the number of changed data
	_, err = io.ReadFull(r.r, r.buf)
	if err != nil {
		return fmt.Errorf("failed to read the number of changed data: %s", err)
	}
	// read changed data
	total := int(r.buf[0] * 2)
	if total > 256 {
		return errors.New("read invalid changed data")
	}
	_, err = io.ReadFull(r.r, r.chg[:total])
	if err != nil {
		return fmt.Errorf("failed to read changed data: %s", err)
	}
	// extract data and update dictionary
	dict := r.dict[idx]
	for i := 0; i < total; i += 2 {
		dict[r.chg[i]] = r.chg[i+1]
	}
	r.data.Write(dict)
	// update status
	r.moveDictionary(idx)
	r.updateLast(dict)
	return nil
}

func (r *cfhReader) reuseLastData() {
	r.data.Write(r.last.Bytes())
}

func (r *cfhReader) reusePreviousData() error {
	// read dictionary index
	_, err := io.ReadFull(r.r, r.buf)
	if err != nil {
		return fmt.Errorf("failed to read dictionary index: %s", err)
	}
	idx := int(r.buf[0])
	dict := r.dict[idx]
	r.data.Write(dict)
	// update status
	r.moveDictionary(idx)
	r.updateLast(dict)
	return nil
}

func (r *cfhReader) moveDictionary(idx int) {
	if idx == 0 {
		return
	}
	dict := r.dict[idx]
	for i := idx; i > 0; i-- {
		r.dict[i] = r.dict[i-1]
	}
	r.dict[0] = dict
}

func (r *cfhReader) updateLast(data []byte) {
	r.last.Reset()
	r.last.Write(data)
}
