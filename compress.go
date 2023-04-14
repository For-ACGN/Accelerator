package accelerator

import (
	"bytes"
	"encoding/binary"
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

const (
	cfhEthernetIPv4TCPSize = 14 + 20 + 20
	cfhEthernetIPv4UDPSize = 14 + 20 + 8
	cfhEthernetIPv6TCPSize = 14 + 40 + 20
	cfhEthernetIPv6UDPSize = 14 + 40 + 8
)

// for select dictionary faster in slowSearchDict.
const (
	cfhMinDiffDiv = 10
	cfhMaxDiffDiv = 4
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
	case size == cfhEthernetIPv4TCPSize:
		return w.fastSearchDictEthernetIPv4TCP(data)
	case size == cfhEthernetIPv4UDPSize:
		return w.fastSearchDictEthernetIPv4UDP(data)
	case size == cfhEthernetIPv6TCPSize:
		return w.fastSearchDictEthernetIPv6TCP(data)
	case size == cfhEthernetIPv6UDPSize:
		return w.fastSearchDictEthernetIPv6UDP(data)
	default:
		return w.slowSearchDict(data)
	}
}

func (w *cfhWriter) fastSearchDictEthernetIPv4TCP(header []byte) int {
	const offset = 14 + (20 - 4*2)
	var dict []byte
	headerP1 := header[:6+6]
	headerP2 := header[offset : offset+4+4+2+2]
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(header) {
			continue
		}
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], headerP1) {
			continue
		}
		// IPv4 src/dst address, TCP/UDP src/dst port
		if !bytes.Equal(dict[offset:offset+4+4+2+2], headerP2) {
			continue
		}
		return i
	}
	return -1
}

func (w *cfhWriter) fastSearchDictEthernetIPv4UDP(header []byte) int {
	const offset = 14 + (20 - 4*2)
	var dict []byte
	headerP1 := header[:6+6]
	headerP2 := header[offset : offset+4+4+2+2]
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(header) {
			continue
		}
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], headerP1) {
			continue
		}
		// IPv4 src/dst address, UDP src/dst port
		if !bytes.Equal(dict[offset:offset+4+4+2+2], headerP2) {
			continue
		}
		return i
	}
	return -1
}

func (w *cfhWriter) fastSearchDictEthernetIPv6TCP(header []byte) int {
	const offset = 14 + (40 - 16*2)
	var dict []byte
	headerP1 := header[:6+6]
	headerP2 := header[offset : offset+16+16+2+2]
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(header) {
			continue
		}
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], headerP1) {
			continue
		}
		// IPv6 src/dst address, TCP/UDP src/dst port
		if !bytes.Equal(dict[offset:offset+16+16+2+2], headerP2) {
			continue
		}
		return i
	}
	return -1
}

func (w *cfhWriter) fastSearchDictEthernetIPv6UDP(header []byte) int {
	const offset = 14 + (40 - 16*2)
	var dict []byte
	headerP1 := header[:6+6]
	headerP2 := header[offset : offset+16+16+2+2]
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(header) {
			continue
		}
		// Ethernet dst/src address
		if !bytes.Equal(dict[:6+6], headerP1) {
			continue
		}
		// IPv6 src/dst address, UDP src/dst port
		if !bytes.Equal(dict[offset:offset+16+16+2+2], headerP2) {
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
	minDiff := len(data) / cfhMinDiffDiv
	maxDiff := len(data) / cfhMaxDiffDiv
	curDiff := cfhMaxDataSize
	dictIdx := -1
next:
	for i := 0; i < len(w.dict); i++ {
		dict = w.dict[i]
		if len(dict) != len(data) {
			continue
		}
		// compare difference
		diff = 0
		for j := 0; j < len(dict); j++ {
			if dict[j] == data[j] {
				continue
			}
			diff++
			// if change a lot, skip current dictionary
			if diff > maxDiff {
				continue next
			}
		}
		// if change a little, select current dictionary
		if diff <= minDiff {
			return i
		}
		// update current minimum difference
		if diff < curDiff {
			curDiff = diff
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
	data []byte
	last bytes.Buffer
	rem  bytes.Buffer
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
	if r.rem.Len() != 0 {
		return r.rem.Read(b)
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
	n := copy(b, r.data)
	if n < len(r.data) {
		r.rem.Write(r.data[n:])
	}
	return n, nil
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
	// update status
	r.data = dict
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
	dict := r.dict[idx]
	if len(dict) < 1 {
		return fmt.Errorf("read invalid dictionary index: %d", idx)
	}
	// read the number of changed data
	_, err = io.ReadFull(r.r, r.buf)
	if err != nil {
		return fmt.Errorf("failed to read the number of changed data: %s", err)
	}
	// read changed data
	size := int(r.buf[0] * 2)
	if size > len(dict)*2 {
		return fmt.Errorf("read invalid changed data size: %d", size/2)
	}
	_, err = io.ReadFull(r.r, r.chg[:size])
	if err != nil {
		return fmt.Errorf("failed to read changed data: %s", err)
	}
	// extract data and update dictionary
	var dataIdx byte
	maxIdx := byte(len(dict) - 1)
	for i := 0; i < size; i += 2 {
		dataIdx = r.chg[i]
		if dataIdx > maxIdx {
			return fmt.Errorf("invalid changed data index: %d", dataIdx)
		}
		dict[dataIdx] = r.chg[i+1]
	}
	// update status
	r.data = dict
	r.moveDictionary(idx)
	r.updateLast(dict)
	return nil
}

func (r *cfhReader) reuseLastData() {
	r.data = r.last.Bytes()
}

func (r *cfhReader) reusePreviousData() error {
	// read dictionary index
	_, err := io.ReadFull(r.r, r.buf)
	if err != nil {
		return fmt.Errorf("failed to read dictionary index: %s", err)
	}
	idx := int(r.buf[0])
	dict := r.dict[idx]
	if len(dict) < 1 {
		return fmt.Errorf("read invalid dictionary index: %d", idx)
	}
	// update status
	r.data = dict
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

// isFrameHeaderPreferBeCompressed is used to check
// frame header can be compressed by fast mode.
// If frame header is preferred be compressed, it
// will return the header size that be compressed.
// It supports IPv4/IPv6 with TCP/UDP
func isFrameHeaderPreferBeCompressed(frame []byte) (int, bool) {
	if len(frame) < cfhEthernetIPv4UDPSize {
		return 0, false
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0800: // IPv4
		// check version is 4 and header length is 20
		if frame[14] != 0x45 {
			return 0, false
		}
		switch frame[23] {
		case 0x06: // TCP
			if len(frame) < cfhEthernetIPv4TCPSize {
				return 0, false
			}
			// check header length is 20
			if frame[46]>>4 != 0x05 {
				return 0, false
			}
			return cfhEthernetIPv4TCPSize, true
		case 0x11: // UDP
			// fixed header length
			return cfhEthernetIPv4UDPSize, true
		default:
			return 0, false
		}
	case 0x86DD: // IPv6
		// fixed header length
		switch frame[20] {
		case 0x06: // TCP
			if len(frame) < cfhEthernetIPv6TCPSize {
				return 0, false
			}
			// check header length is 20
			if frame[66]>>4 != 0x05 {
				return 0, false
			}
			return cfhEthernetIPv6TCPSize, true
		case 0x11: // UDP
			if len(frame) < cfhEthernetIPv6UDPSize {
				return 0, false
			}
			// fixed header length
			return cfhEthernetIPv6UDPSize, true
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}
