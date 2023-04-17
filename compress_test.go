package accelerator

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/require"
)

var (
	testEthernet1 = "d8ba1192c572d8af159ac5d10800" // IPv4
	testEthernet2 = "d8ba1192c572d8af159ac5d20800" // IPv4
	testEthernet3 = "d8ba1192c572d8af159ac5d386dd" // IPv6
	testEthernet4 = "d8ba1192c572d8af159ac5d486dd" // IPv6

	testIPv4H1 = "450405c8574d40003706b63514983c5fc0a81f0a" // TCP
	testIPv4H2 = "450405c8575d40003706b63514983c5fc0a81f0a" // TCP
	testIPv4H3 = "450405c8576d40003711b63514983c5fc0a81f0a" // UDP
	testIPv4H4 = "450405c8577d40003711b63514983c5fc0a81f0a" // UDP

	testIPv6H1 = "6043670105a0062b24108c016c2a103d000000afb00239ab24108a2aa084b4a02127e9cada1240f1" // TCP
	testIPv6H2 = "6043670205a0062b24108c016c2a103d000000afb00239ab24108a2aa084b4a02127e9cada1240f1" // TCP
	testIPv6H3 = "6043670305a0112b24108c016c2a103d000000afb00239ab24108a2aa084b4a02127e9cada1240f1" // UDP
	testIPv6H4 = "6043670405a0112b24108c016c2a103d000000afb00239ab24108a2aa084b4a02127e9cada1240f1" // UDP

	testTCPH1 = "01bbebd71561ddfc151e1385501003d037390000"
	testTCPH2 = "01bbebd81661ddfc151e1385501003d037390000"

	testUDPH1 = "fb7b003500385f66"
	testUDPH2 = "fb7b003600385f66"

	testIPv4TCPFrameHeader1 = testMustHexDecodeString(testEthernet1 + testIPv4H1 + testTCPH1)
	testIPv4TCPFrameHeader2 = testMustHexDecodeString(testEthernet1 + testIPv4H1 + testTCPH2)
	testIPv4TCPFrameHeader3 = testMustHexDecodeString(testEthernet1 + testIPv4H2 + testTCPH1)
	testIPv4TCPFrameHeader4 = testMustHexDecodeString(testEthernet1 + testIPv4H2 + testTCPH2)
	testIPv4TCPFrameHeader5 = testMustHexDecodeString(testEthernet2 + testIPv4H1 + testTCPH1)
	testIPv4TCPFrameHeader6 = testMustHexDecodeString(testEthernet2 + testIPv4H1 + testTCPH2)
	testIPv4TCPFrameHeader7 = testMustHexDecodeString(testEthernet2 + testIPv4H2 + testTCPH1)
	testIPv4TCPFrameHeader8 = testMustHexDecodeString(testEthernet2 + testIPv4H2 + testTCPH2)

	testIPv4UDPFrameHeader1 = testMustHexDecodeString(testEthernet1 + testIPv4H3 + testUDPH1)
	testIPv4UDPFrameHeader2 = testMustHexDecodeString(testEthernet1 + testIPv4H3 + testUDPH2)
	testIPv4UDPFrameHeader3 = testMustHexDecodeString(testEthernet1 + testIPv4H4 + testUDPH1)
	testIPv4UDPFrameHeader4 = testMustHexDecodeString(testEthernet1 + testIPv4H4 + testUDPH2)
	testIPv4UDPFrameHeader5 = testMustHexDecodeString(testEthernet2 + testIPv4H3 + testUDPH1)
	testIPv4UDPFrameHeader6 = testMustHexDecodeString(testEthernet2 + testIPv4H3 + testUDPH2)
	testIPv4UDPFrameHeader7 = testMustHexDecodeString(testEthernet2 + testIPv4H4 + testUDPH1)
	testIPv4UDPFrameHeader8 = testMustHexDecodeString(testEthernet2 + testIPv4H4 + testUDPH2)

	testIPv6TCPFrameHeader1 = testMustHexDecodeString(testEthernet3 + testIPv6H1 + testTCPH1)
	testIPv6TCPFrameHeader2 = testMustHexDecodeString(testEthernet3 + testIPv6H1 + testTCPH2)
	testIPv6TCPFrameHeader3 = testMustHexDecodeString(testEthernet3 + testIPv6H2 + testTCPH1)
	testIPv6TCPFrameHeader4 = testMustHexDecodeString(testEthernet3 + testIPv6H2 + testTCPH2)
	testIPv6TCPFrameHeader5 = testMustHexDecodeString(testEthernet4 + testIPv6H1 + testTCPH1)
	testIPv6TCPFrameHeader6 = testMustHexDecodeString(testEthernet4 + testIPv6H1 + testTCPH2)
	testIPv6TCPFrameHeader7 = testMustHexDecodeString(testEthernet4 + testIPv6H2 + testTCPH1)
	testIPv6TCPFrameHeader8 = testMustHexDecodeString(testEthernet4 + testIPv6H2 + testTCPH2)

	testIPv6UDPFrameHeader1 = testMustHexDecodeString(testEthernet3 + testIPv6H3 + testUDPH1)
	testIPv6UDPFrameHeader2 = testMustHexDecodeString(testEthernet3 + testIPv6H3 + testUDPH2)
	testIPv6UDPFrameHeader3 = testMustHexDecodeString(testEthernet3 + testIPv6H4 + testUDPH1)
	testIPv6UDPFrameHeader4 = testMustHexDecodeString(testEthernet3 + testIPv6H4 + testUDPH2)
	testIPv6UDPFrameHeader5 = testMustHexDecodeString(testEthernet4 + testIPv6H3 + testUDPH1)
	testIPv6UDPFrameHeader6 = testMustHexDecodeString(testEthernet4 + testIPv6H3 + testUDPH2)
	testIPv6UDPFrameHeader7 = testMustHexDecodeString(testEthernet4 + testIPv6H4 + testUDPH1)
	testIPv6UDPFrameHeader8 = testMustHexDecodeString(testEthernet4 + testIPv6H4 + testUDPH2)
)

var testFrameHeaders = [][]byte{
	testIPv4TCPFrameHeader1, testIPv4TCPFrameHeader2, testIPv4TCPFrameHeader3, testIPv4TCPFrameHeader4,
	testIPv4TCPFrameHeader5, testIPv4TCPFrameHeader6, testIPv4TCPFrameHeader7, testIPv4TCPFrameHeader8,

	testIPv4UDPFrameHeader1, testIPv4UDPFrameHeader2, testIPv4UDPFrameHeader3, testIPv4UDPFrameHeader4,
	testIPv4UDPFrameHeader5, testIPv4UDPFrameHeader6, testIPv4UDPFrameHeader7, testIPv4UDPFrameHeader8,

	testIPv6TCPFrameHeader1, testIPv6TCPFrameHeader2, testIPv6TCPFrameHeader3, testIPv6TCPFrameHeader4,
	testIPv6TCPFrameHeader5, testIPv6TCPFrameHeader6, testIPv6TCPFrameHeader7, testIPv6TCPFrameHeader8,

	testIPv6UDPFrameHeader1, testIPv6UDPFrameHeader2, testIPv6UDPFrameHeader3, testIPv6UDPFrameHeader4,
	testIPv6UDPFrameHeader5, testIPv6UDPFrameHeader6, testIPv6UDPFrameHeader7, testIPv6UDPFrameHeader8,
}

func testMustHexDecodeString(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func testGenerateFrameHeaders(t *testing.T) [][]byte {
	headers := make([][]byte, 64*1024)
	typ := make([]byte, 1)
	idx := make([]byte, 2)
	for i := 0; i < len(headers); i++ {
		// select frame header type
		_, err := rand.Read(typ)
		require.NoError(t, err)
		switch typ[0] % 5 {
		case 0: // IPv4 + TCP
			header := make([]byte, cfhEthernetIPv4TCPSize)
			copy(header, testIPv4TCPFrameHeader1)
			// random change data
			for j := 0; j < 3; j++ {
				_, err = rand.Read(idx)
				require.NoError(t, err)
				index := binary.BigEndian.Uint16(idx) % cfhEthernetIPv4TCPSize
				header[index] = idx[1]
			}
			headers[i] = header
		case 1: // IPv4 + UDP
			header := make([]byte, cfhEthernetIPv4UDPSize)
			copy(header, testIPv4UDPFrameHeader1)
			// random change data
			for j := 0; j < 2; j++ {
				_, err = rand.Read(idx)
				require.NoError(t, err)
				index := binary.BigEndian.Uint16(idx) % cfhEthernetIPv4UDPSize
				header[index] = idx[1]
			}
			headers[i] = header
		case 2: // IPv6 + TCP
			header := make([]byte, cfhEthernetIPv6TCPSize)
			copy(header, testIPv6TCPFrameHeader1)
			// random change data
			for j := 0; j < 2; j++ {
				_, err = rand.Read(idx)
				require.NoError(t, err)
				index := binary.BigEndian.Uint16(idx) % cfhEthernetIPv6TCPSize
				header[index] = idx[1]
			}
			headers[i] = header
		case 3: // IPv6 + UDP
			header := make([]byte, cfhEthernetIPv6UDPSize)
			copy(header, testIPv6UDPFrameHeader1)
			// random change data
			for j := 0; j < 1; j++ {
				_, err = rand.Read(idx)
				require.NoError(t, err)
				index := binary.BigEndian.Uint16(idx) % cfhEthernetIPv6UDPSize
				header[index] = idx[1]
			}
			headers[i] = header
		case 4: // random length
			sizeBuf := make([]byte, 1)
			var size byte
			for size < 32 {
				_, err = rand.Read(sizeBuf)
				require.NoError(t, err)
				size = sizeBuf[0]
			}
			header := make([]byte, size)
			_, err = rand.Read(header)
			require.NoError(t, err)
			// at the end of the generated headers
			if i > len(headers)-10 {
				headers[i] = header
				continue
			}
			// append similar frame headers
			sHeader1 := make([]byte, size)
			copy(sHeader1, header)
			for j := 0; j < len(header)/cfhMinDiffDiv+2; j++ {
				sHeader1[j+10]++
			}
			sHeader2 := make([]byte, size)
			copy(sHeader2, header)
			for j := 0; j < len(header)/cfhMinDiffDiv+3; j++ {
				sHeader2[j+10]++
			}
			headers[i] = header
			headers[i+1] = sHeader1
			headers[i+2] = sHeader2
			i += 2
		}
	}
	return headers
}

func TestNewCFHWriter(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		w := newCFHWriter(output)
		require.NotNil(t, w)
	})

	t.Run("too small dictionary size", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		w, err := newCFHWriterWithSize(output, 0)
		require.EqualError(t, err, "dictionary size cannot less than 1")
		require.Nil(t, w)
	})

	t.Run("too large dictionary size", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		w, err := newCFHWriterWithSize(output, 4096)
		require.EqualError(t, err, "dictionary size cannot greater than 256")
		require.Nil(t, w)
	})

	t.Run("panic with default parameters", func(t *testing.T) {
		outputs := []interface{}{nil, errors.New("monkey error")}
		patch := gomonkey.ApplyFuncReturn(newCFHWriterWithSize, outputs...)
		defer patch.Reset()

		output := bytes.NewBuffer(make([]byte, 0, 64))

		defer func() {
			r := recover()
			require.NotNil(t, r)
		}()
		_ = newCFHWriter(output)
	})
}

func TestCFHWriter_Write(t *testing.T) {
	output := bytes.NewBuffer(make([]byte, 0, 4096))

	t.Run("write as same as the last", func(t *testing.T) {
		w := newCFHWriter(output)
		for i := 0; i < 100; i++ {
			n, err := w.Write(testIPv4TCPFrameHeader1)
			require.NoError(t, err)
			require.Equal(t, len(testIPv4TCPFrameHeader1), n)
		}

		r := newCFHReader(output)
		buf := make([]byte, len(testIPv4TCPFrameHeader1))
		for i := 0; i < 100; i++ {
			n, err := r.Read(buf)
			require.NoError(t, err)
			require.Equal(t, len(testIPv4TCPFrameHeader1), n)
			require.Equal(t, testIPv4TCPFrameHeader1, buf)
		}
	})

	t.Run("write as same as the previous", func(t *testing.T) {
		w := newCFHWriter(output)

		n, err := w.Write(testIPv4TCPFrameHeader1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)

		n, err = w.Write(testIPv4TCPFrameHeader2)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader2), n)

		n, err = w.Write(testIPv4TCPFrameHeader1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)

		r := newCFHReader(output)

		buf := make([]byte, len(testIPv4TCPFrameHeader1))
		n, err = r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)
		require.Equal(t, testIPv4TCPFrameHeader1, buf)

		buf = make([]byte, len(testIPv4TCPFrameHeader2))
		n, err = r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader2), n)
		require.Equal(t, testIPv4TCPFrameHeader2, buf)

		buf = make([]byte, len(testIPv4TCPFrameHeader1))
		n, err = r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)
		require.Equal(t, testIPv4TCPFrameHeader1, buf)
	})

	t.Run("write empty data", func(t *testing.T) {
		w := newCFHWriter(output)

		n, err := w.Write(nil)
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("write too large data", func(t *testing.T) {
		w := newCFHWriter(output)

		data := bytes.Repeat([]byte{0}, cfhMaxFrameHeaderSize+1)
		n, err := w.Write(data)
		require.EqualError(t, err, "write too large data")
		require.Zero(t, n)
	})

	t.Run("write after appear error", func(t *testing.T) {
		pr, pw := io.Pipe()
		err := pr.Close()
		require.NoError(t, err)

		w := newCFHWriter(pw)

		n, err := w.Write(testIPv4TCPFrameHeader1)
		require.Equal(t, io.ErrClosedPipe, err)
		require.Zero(t, n)

		n, err = w.Write(testIPv4TCPFrameHeader1)
		require.Equal(t, io.ErrClosedPipe, err)
		require.Zero(t, n)

		err = pw.Close()
		require.NoError(t, err)
	})

	t.Run("failed to write last", func(t *testing.T) {
		pr, pw := io.Pipe()
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1024)
			_, err := pr.Read(buf)
			require.NoError(t, err)
		}()

		w := newCFHWriter(pw)

		n, err := w.Write(testIPv4TCPFrameHeader1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)

		wg.Wait()

		err = pr.Close()
		require.NoError(t, err)

		n, err = w.Write(testIPv4TCPFrameHeader1)
		require.Equal(t, io.ErrClosedPipe, err)
		require.Zero(t, n)

		err = pw.Close()
		require.NoError(t, err)
	})

	t.Run("failed to write changed data", func(t *testing.T) {
		pr, pw := io.Pipe()
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1024)
			_, err := pr.Read(buf)
			require.NoError(t, err)
			_, err = pr.Read(buf)
			require.NoError(t, err)
		}()

		w := newCFHWriter(pw)

		n, err := w.Write(testIPv4TCPFrameHeader1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)

		n, err = w.Write(testIPv4TCPFrameHeader2)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader2), n)

		wg.Wait()

		err = pr.Close()
		require.NoError(t, err)

		n, err = w.Write(testIPv4TCPFrameHeader1)
		require.Equal(t, io.ErrClosedPipe, err)
		require.Zero(t, n)

		err = pw.Close()
		require.NoError(t, err)
	})
}

func TestCFHWriter_searchDictionary(t *testing.T) {
	t.Run("fast", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 4096))

		w := newCFHWriter(output)
		for _, header := range testFrameHeaders {
			n, err := w.Write(header)
			require.NoError(t, err)
			require.Equal(t, len(header), n)
		}

		r := newCFHReader(output)
		for _, header := range testFrameHeaders {
			buf := make([]byte, len(header))
			n, err := r.Read(buf)
			require.NoError(t, err)
			require.Equal(t, len(header), n)
			require.Equal(t, header, buf)
		}
	})

	t.Run("slow", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 4096))

		headers := testFrameHeaders
		for i := 0; i < 16; i++ {
			noise := make([]byte, 64)
			_, err := rand.Read(noise)
			require.NoError(t, err)
			headers = append(headers, noise)
		}

		// append similar frame headers
		header := make([]byte, 64)
		_, err := rand.Read(header)
		require.NoError(t, err)
		sHeader1 := make([]byte, 64)
		copy(sHeader1, header)
		for i := 0; i < len(header)/cfhMinDiffDiv+2; i++ {
			sHeader1[i+10]++
		}
		sHeader2 := make([]byte, 64)
		copy(sHeader2, header)
		for i := 0; i < len(header)/cfhMinDiffDiv+3; i++ {
			sHeader2[i+10]++
		}
		headers = append(headers, header, sHeader1, sHeader2)

		w := newCFHWriter(output)
		for _, h := range headers {
			nh := append(h, 0)
			n, err := w.Write(nh)
			require.NoError(t, err)
			require.Equal(t, len(nh), n)
		}

		r := newCFHReader(output)
		for _, h := range headers {
			nh := append(h, 0)
			buf := make([]byte, len(nh))
			n, err := r.Read(buf)
			require.NoError(t, err)
			require.Equal(t, len(nh), n)
			require.Equal(t, nh, buf)
		}
	})
}

func TestNewCFHReader(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		r := newCFHReader(output)
		require.NotNil(t, r)
	})

	t.Run("too small dictionary size", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		r, err := newCFHReaderWithSize(output, 0)
		require.EqualError(t, err, "dictionary size cannot less than 1")
		require.Nil(t, r)
	})

	t.Run("too large dictionary size", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		r, err := newCFHReaderWithSize(output, 4096)
		require.EqualError(t, err, "dictionary size cannot greater than 256")
		require.Nil(t, r)
	})

	t.Run("panic with default parameters", func(t *testing.T) {
		outputs := []interface{}{nil, errors.New("monkey error")}
		patch := gomonkey.ApplyFuncReturn(newCFHReaderWithSize, outputs...)
		defer patch.Reset()

		output := bytes.NewBuffer(make([]byte, 0, 64))

		defer func() {
			r := recover()
			require.NotNil(t, r)
		}()
		_ = newCFHReader(output)
	})
}

func TestCFHReader_Read(t *testing.T) {
	t.Run("read remaining data", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 128))

		w := newCFHWriter(output)

		n, err := w.Write(testIPv4TCPFrameHeader1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrameHeader1), n)

		r := newCFHReader(output)

		buf1 := make([]byte, len(testIPv4TCPFrameHeader1)-16)
		n, err = r.Read(buf1)
		require.NoError(t, err)
		require.Equal(t, len(buf1), n)

		buf2 := make([]byte, 16)
		n, err = r.Read(buf2)
		require.NoError(t, err)
		require.Equal(t, len(buf2), n)

		require.Equal(t, testIPv4TCPFrameHeader1, append(buf1, buf2...))
	})

	t.Run("read empty buffer", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 128))
		r := newCFHReader(output)

		n, err := r.Read(nil)
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("read with too large buffer", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		r := newCFHReader(output)

		buf := make([]byte, 1024)
		n, err := r.Read(buf)
		require.EqualError(t, err, "read with too large buffer")
		require.Zero(t, n)
	})

	t.Run("read after appear error", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		r := newCFHReader(output)

		buf := make([]byte, cfhMaxFrameHeaderSize)
		n, err := r.Read(buf)
		require.EqualError(t, err, "failed to read decompress command: EOF")
		require.Zero(t, n)

		n, err = r.Read(buf)
		require.EqualError(t, err, "failed to read decompress command: EOF")
		require.Zero(t, n)
	})

	t.Run("failed to read decompress command", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))

		r := newCFHReader(output)

		buf := make([]byte, cfhMaxFrameHeaderSize)
		n, err := r.Read(buf)
		require.EqualError(t, err, "failed to read decompress command: EOF")
		require.Zero(t, n)
	})

	t.Run("invalid decompress command", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))
		output.WriteByte(0)

		r := newCFHReader(output)

		buf := make([]byte, cfhMaxFrameHeaderSize)
		n, err := r.Read(buf)
		require.EqualError(t, err, "invalid decompress command: 0")
		require.Zero(t, n)
	})

	t.Run("add dictionary", func(t *testing.T) {
		t.Run("failed to read dictionary size", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDAddDict)

			r := newCFHReader(output)

			buf := make([]byte, cfhMaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary size: EOF")
			require.Zero(t, n)
		})

		t.Run("read empty dictionary", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDAddDict)
			output.WriteByte(0) // dictionary size

			r := newCFHReader(output)

			buf := make([]byte, cfhMaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read empty dictionary")
			require.Zero(t, n)
		})

		t.Run("failed to read dictionary data", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDAddDict)
			output.WriteByte(1) // dictionary size

			r := newCFHReader(output)

			buf := make([]byte, cfhMaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary data: EOF")
			require.Zero(t, n)
		})
	})

	t.Run("read changed data", func(t *testing.T) {
		t.Run("failed to read dictionary index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDData)

			r := newCFHReader(output)

			buf := make([]byte, cfhMaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary index: EOF")
			require.Zero(t, n)
		})

		t.Run("read invalid dictionary index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDData)
			output.WriteByte(0) // dictionary index

			r := newCFHReader(output)

			buf := make([]byte, cfhMaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read invalid dictionary index: 0")
			require.Zero(t, n)
		})

		t.Run("failed to read the number of changed data", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDData)
			output.WriteByte(0) // dictionary index

			r := newCFHReader(output)
			r.(*cfhReader).dict[0] = []byte{1, 2, 3, 4}

			buf := make([]byte, cfhMaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read the number of changed data: EOF")
			require.Zero(t, n)
		})

		t.Run("read invalid changed data", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDData)
			output.WriteByte(0) // dictionary index
			output.WriteByte(5) // the number of changed data

			r := newCFHReader(output)
			r.(*cfhReader).dict[0] = []byte{1, 2, 3, 4}

			buf := make([]byte, cfhMaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read invalid changed data size: 5")
			require.Zero(t, n)
		})

		t.Run("failed to read changed data", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDData)
			output.WriteByte(0) // dictionary index
			output.WriteByte(2) // the number of changed data

			r := newCFHReader(output)
			r.(*cfhReader).dict[0] = []byte{1, 2, 3, 4}

			buf := make([]byte, cfhMaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read changed data: EOF")
			require.Zero(t, n)
		})

		t.Run("invalid changed data index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDData)
			output.WriteByte(0)   // dictionary index
			output.WriteByte(1)   // the number of changed data
			output.WriteByte(4)   // changed data index
			output.WriteByte(123) // changed data

			r := newCFHReader(output)
			r.(*cfhReader).dict[0] = []byte{1, 2, 3, 4}

			buf := make([]byte, cfhMaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "invalid changed data index: 4")
			require.Zero(t, n)
		})
	})

	t.Run("reuse previous data", func(t *testing.T) {
		t.Run("failed to read dictionary index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDPrev)

			r := newCFHReader(output)

			buf := make([]byte, cfhMaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary index: EOF")
			require.Zero(t, n)
		})

		t.Run("read invalid dictionary index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDPrev)
			output.WriteByte(0) // dictionary index

			r := newCFHReader(output)

			buf := make([]byte, cfhMaxFrameHeaderSize)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read invalid dictionary index: 0")
			require.Zero(t, n)
		})
	})
}

func TestIsFrameHeaderPreferBeCompressed(t *testing.T) {
	t.Run("Ethernet IPv4 TCP", func(t *testing.T) {
		for _, header := range [][]byte{
			testIPv4TCPFrameHeader1,
			testIPv4TCPFrameHeader2,
			testIPv4TCPFrameHeader3,
			testIPv4TCPFrameHeader4,
			testIPv4TCPFrameHeader5,
			testIPv4TCPFrameHeader6,
			testIPv4TCPFrameHeader7,
			testIPv4TCPFrameHeader8,
		} {
			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.True(t, prefer)
			require.Equal(t, cfhEthernetIPv4TCPSize, size)
		}
	})

	t.Run("Ethernet IPv4 UDP", func(t *testing.T) {
		for _, header := range [][]byte{
			testIPv4UDPFrameHeader1,
			testIPv4UDPFrameHeader2,
			testIPv4UDPFrameHeader3,
			testIPv4UDPFrameHeader4,
			testIPv4UDPFrameHeader5,
			testIPv4UDPFrameHeader6,
			testIPv4UDPFrameHeader7,
			testIPv4UDPFrameHeader8,
		} {
			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.True(t, prefer)
			require.Equal(t, cfhEthernetIPv4UDPSize, size)
		}
	})

	t.Run("Ethernet IPv6 TCP", func(t *testing.T) {
		for _, header := range [][]byte{
			testIPv6TCPFrameHeader1,
			testIPv6TCPFrameHeader2,
			testIPv6TCPFrameHeader3,
			testIPv6TCPFrameHeader4,
			testIPv6TCPFrameHeader5,
			testIPv6TCPFrameHeader6,
			testIPv6TCPFrameHeader7,
			testIPv6TCPFrameHeader8,
		} {
			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.True(t, prefer)
			require.Equal(t, cfhEthernetIPv6TCPSize, size)
		}
	})

	t.Run("Ethernet IPv6 UDP", func(t *testing.T) {
		for _, header := range [][]byte{
			testIPv6UDPFrameHeader1,
			testIPv6UDPFrameHeader2,
			testIPv6UDPFrameHeader3,
			testIPv6UDPFrameHeader4,
			testIPv6UDPFrameHeader5,
			testIPv6UDPFrameHeader6,
			testIPv6UDPFrameHeader7,
			testIPv6UDPFrameHeader8,
		} {
			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.True(t, prefer)
			require.Equal(t, cfhEthernetIPv6UDPSize, size)
		}
	})

	t.Run("too small frame", func(t *testing.T) {
		size, prefer := isFrameHeaderPreferBeCompressed([]byte{})
		require.False(t, prefer)
		require.Zero(t, size)
	})

	t.Run("other network layer", func(t *testing.T) {
		header := make([]byte, len(testIPv4TCPFrameHeader1))
		copy(header, testIPv4TCPFrameHeader1)
		header[12] = 0xFF // next layer type
		header[13] = 0xFF // next layer type

		size, prefer := isFrameHeaderPreferBeCompressed(header)
		require.False(t, prefer)
		require.Zero(t, size)
	})

	t.Run("IPv4", func(t *testing.T) {
		t.Run("with options", func(t *testing.T) {
			header := make([]byte, len(testIPv4TCPFrameHeader1))
			copy(header, testIPv4TCPFrameHeader1)
			header[14] = 0x46 // header length is not 20

			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.False(t, prefer)
			require.Zero(t, size)
		})

		t.Run("other transport layer", func(t *testing.T) {
			header := make([]byte, len(testIPv4TCPFrameHeader1))
			copy(header, testIPv4TCPFrameHeader1)
			header[23] = 0xFF

			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.False(t, prefer)
			require.Zero(t, size)
		})

		t.Run("TCP", func(t *testing.T) {
			t.Run("invalid frame size", func(t *testing.T) {
				header := make([]byte, len(testIPv4TCPFrameHeader1)-1)
				copy(header, testIPv4TCPFrameHeader1)

				size, prefer := isFrameHeaderPreferBeCompressed(header)
				require.False(t, prefer)
				require.Zero(t, size)
			})

			t.Run("with options", func(t *testing.T) {
				header := make([]byte, len(testIPv4TCPFrameHeader1))
				copy(header, testIPv4TCPFrameHeader1)
				header[46] = 0xFF

				size, prefer := isFrameHeaderPreferBeCompressed(header)
				require.False(t, prefer)
				require.Zero(t, size)
			})
		})
	})

	t.Run("IPv6", func(t *testing.T) {
		t.Run("other transport layer", func(t *testing.T) {
			header := make([]byte, len(testIPv6TCPFrameHeader1))
			copy(header, testIPv6TCPFrameHeader1)
			header[20] = 0xFF

			size, prefer := isFrameHeaderPreferBeCompressed(header)
			require.False(t, prefer)
			require.Zero(t, size)
		})

		t.Run("TCP", func(t *testing.T) {
			t.Run("invalid frame size", func(t *testing.T) {
				header := make([]byte, len(testIPv6TCPFrameHeader1)-1)
				copy(header, testIPv6TCPFrameHeader1)

				size, prefer := isFrameHeaderPreferBeCompressed(header)
				require.False(t, prefer)
				require.Zero(t, size)
			})

			t.Run("with options", func(t *testing.T) {
				header := make([]byte, len(testIPv6TCPFrameHeader1))
				copy(header, testIPv6TCPFrameHeader1)
				header[66] = 0xFF

				size, prefer := isFrameHeaderPreferBeCompressed(header)
				require.False(t, prefer)
				require.Zero(t, size)
			})
		})

		t.Run("UDP", func(t *testing.T) {
			t.Run("invalid frame size", func(t *testing.T) {
				header := make([]byte, len(testIPv6UDPFrameHeader1)-1)
				copy(header, testIPv6UDPFrameHeader1)

				size, prefer := isFrameHeaderPreferBeCompressed(header)
				require.False(t, prefer)
				require.Zero(t, size)
			})
		})
	})
}

func TestCFHWriter_Fuzz(t *testing.T) {
	output := bytes.NewBuffer(make([]byte, 0, 4*1024*1024))
	headers := testGenerateFrameHeaders(t)

	w := newCFHWriter(output)
	for _, header := range headers {
		n, err := w.Write(header)
		require.NoError(t, err)
		require.Equal(t, len(header), n)
	}

	r := newCFHReader(output)
	for _, header := range headers {
		buf := make([]byte, len(header))
		n, err := r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(header), n)
		require.Equal(t, header, buf)
	}
}

func TestCFHReader_Fuzz(t *testing.T) {
	data := make([]byte, 128)
	reader := bytes.NewReader(data)
	buf := make([]byte, cfhMaxFrameHeaderSize)
	for i := 0; i < 128*1024; i++ {
		_, err := rand.Read(data)
		require.NoError(t, err)
		_, err = reader.Seek(0, io.SeekStart)
		require.NoError(t, err)

		r := newCFHReader(reader)
		_, _ = r.Read(buf)
	}
}

func TestIsFrameHeaderPreferBeCompressed_Fuzz(t *testing.T) {
	headers := testGenerateFrameHeaders(t)
	for _, header := range headers {
		f := append(header, 0)
		size, prefer := isFrameHeaderPreferBeCompressed(f)
		if !prefer {
			continue
		}
		switch size {
		case cfhEthernetIPv4TCPSize:
		case cfhEthernetIPv4UDPSize:
		case cfhEthernetIPv6TCPSize:
		case cfhEthernetIPv6UDPSize:
		default:
			t.Fatalf("invalid size: %d", size)
		}
	}
}

func BenchmarkCFHWriter_Write(b *testing.B) {
	b.Run("Ethernet IPv4 TCP", benchmarkCFHWriterWriteEthernetIPv4TCP)
	b.Run("Ethernet IPv4 UDP", benchmarkCFHWriterWriteEthernetIPv4UDP)
	b.Run("Ethernet IPv6 TCP", benchmarkCFHWriterWriteEthernetIPv6TCP)
	b.Run("Ethernet IPv6 UDP", benchmarkCFHWriterWriteEthernetIPv6UDP)
	b.Run("Custom Frame Header", benchmarkCFHWriterWriteCustomFrameHeader)
}

func benchmarkCFHWriterWriteEthernetIPv4TCP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv4TCPFrameHeader1))
		copy(header, testIPv4TCPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			header[19] = byte(i) + 2 // IPv4 ID [byte 2]
			header[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			header[41] = byte(i) + 4 // TCP Sequence [byte 4]
			header[45] = byte(i) + 5 // TCP acknowledgment [byte 4]
			header[50] = byte(i) + 6 // TCP checksum [byte 1]
			header[51] = byte(i) + 7 // TCP checksum [byte 2]
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv4TCPFrameHeader1))
		copy(header, testIPv4TCPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			header[19] = byte(i) + 2 // IPv4 ID [byte 2]
			header[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			header[41] = byte(i) + 4 // TCP Sequence [byte 4]
			header[45] = byte(i) + 5 // TCP acknowledgment [byte 4]
			header[50] = byte(i) + 6 // TCP checksum [byte 1]
			header[51] = byte(i) + 7 // TCP checksum [byte 2]

			// change destination port for create more dictionaries
			header[34] = byte(i) + 8
		}

		b.StopTimer()
	})
}

func benchmarkCFHWriterWriteEthernetIPv4UDP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv4UDPFrameHeader1))
		copy(header, testIPv4UDPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			header[19] = byte(i) + 2 // IPv4 ID [byte 2]
			header[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			header[39] = byte(i) + 4 // UDP length [byte 4]
			header[40] = byte(i) + 5 // UDP checksum [byte 1]
			header[41] = byte(i) + 6 // UDP checksum [byte 2]
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv4UDPFrameHeader1))
		copy(header, testIPv4UDPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			header[19] = byte(i) + 2 // IPv4 ID [byte 2]
			header[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			header[39] = byte(i) + 4 // UDP length [byte 4]
			header[40] = byte(i) + 5 // UDP checksum [byte 1]
			header[41] = byte(i) + 6 // UDP checksum [byte 2]

			// change destination port for create more dictionaries
			header[34] = byte(i) + 7
		}

		b.StopTimer()
	})
}

func benchmarkCFHWriterWriteEthernetIPv6TCP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv6TCPFrameHeader1))
		copy(header, testIPv6TCPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			header[61] = byte(i) + 2 // TCP Sequence [byte 4]
			header[65] = byte(i) + 3 // TCP acknowledgment [byte 4]
			header[70] = byte(i) + 4 // TCP checksum [byte 1]
			header[71] = byte(i) + 5 // TCP checksum [byte 2]
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv6TCPFrameHeader1))
		copy(header, testIPv6TCPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			header[61] = byte(i) + 2 // TCP Sequence [byte 4]
			header[65] = byte(i) + 3 // TCP acknowledgment [byte 4]
			header[70] = byte(i) + 4 // TCP checksum [byte 1]
			header[71] = byte(i) + 5 // TCP checksum [byte 2]

			// change destination port for create more dictionaries
			header[54] = byte(i) + 6
		}

		b.StopTimer()
	})
}

func benchmarkCFHWriterWriteEthernetIPv6UDP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv6UDPFrameHeader1))
		copy(header, testIPv6UDPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			header[59] = byte(i) + 2 // UDP length [byte 4]
			header[60] = byte(i) + 3 // UDP checksum [byte 1]
			header[61] = byte(i) + 4 // UDP checksum [byte 2]
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv6UDPFrameHeader1))
		copy(header, testIPv6UDPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			header[59] = byte(i) + 2 // UDP length [byte 4]
			header[60] = byte(i) + 3 // UDP checksum [byte 1]
			header[61] = byte(i) + 4 // UDP checksum [byte 2]

			// change destination port for create more dictionaries
			header[54] = byte(i) + 5
		}

		b.StopTimer()
	})
}

func benchmarkCFHWriterWriteCustomFrameHeader(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, 64)
		copy(header, testIPv4TCPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// change a little
			for j := 0; j < len(header)/cfhMinDiffDiv-2; j++ {
				header[j] = byte(i) + 1
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, 64)
		copy(header, testIPv4TCPFrameHeader1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// change a lot
			for j := 0; j < len(header)/cfhMaxDiffDiv+2; j++ {
				header[j] = byte(i) + 1
			}
		}

		b.StopTimer()
	})
}

func BenchmarkCFHReader_Read(b *testing.B) {
	b.Run("Ethernet IPv4 TCP", benchmarkCFHReaderReadEthernetIPv4TCP)
	b.Run("Ethernet IPv4 UDP", benchmarkCFHReaderReadEthernetIPv4UDP)
	b.Run("Ethernet IPv6 TCP", benchmarkCFHReaderReadEthernetIPv6TCP)
	b.Run("Ethernet IPv6 UDP", benchmarkCFHReaderReadEthernetIPv6UDP)
	b.Run("Custom Frame Header", benchmarkCFHReaderReadCustomFrameHeader)
}

func benchmarkCFHReaderReadEthernetIPv4TCP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv4TCPFrameHeader1))
		copy(header, testIPv4TCPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			header[19] = byte(i) + 2 // IPv4 ID [byte 2]
			header[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			header[41] = byte(i) + 4 // TCP Sequence [byte 4]
			header[45] = byte(i) + 5 // TCP acknowledgment [byte 4]
			header[50] = byte(i) + 6 // TCP checksum [byte 1]
			header[51] = byte(i) + 7 // TCP checksum [byte 2]
		}

		reader := bytes.NewReader(output.Bytes())

		r := newCFHReader(reader)
		buf := make([]byte, len(testIPv4TCPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv4TCPFrameHeader1))
		copy(header, testIPv4TCPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			header[19] = byte(i) + 2 // IPv4 ID [byte 2]
			header[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			header[41] = byte(i) + 4 // TCP Sequence [byte 4]
			header[45] = byte(i) + 5 // TCP acknowledgment [byte 4]
			header[50] = byte(i) + 6 // TCP checksum [byte 1]
			header[51] = byte(i) + 7 // TCP checksum [byte 2]

			// change destination port for create more dictionaries
			header[34] = byte(i) + 8
		}

		reader := bytes.NewReader(output.Bytes())

		r := newCFHReader(reader)
		buf := make([]byte, len(testIPv4TCPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})
}

func benchmarkCFHReaderReadEthernetIPv4UDP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv4UDPFrameHeader1))
		copy(header, testIPv4UDPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			header[19] = byte(i) + 2 // IPv4 ID [byte 2]
			header[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			header[39] = byte(i) + 4 // UDP length [byte 4]
			header[40] = byte(i) + 5 // UDP checksum [byte 1]
			header[41] = byte(i) + 6 // UDP checksum [byte 2]
		}

		reader := bytes.NewReader(output.Bytes())

		r := newCFHReader(reader)
		buf := make([]byte, len(testIPv4UDPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv4UDPFrameHeader1))
		copy(header, testIPv4UDPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			header[19] = byte(i) + 2 // IPv4 ID [byte 2]
			header[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			header[39] = byte(i) + 4 // UDP length [byte 4]
			header[40] = byte(i) + 5 // UDP checksum [byte 1]
			header[41] = byte(i) + 6 // UDP checksum [byte 2]

			// change destination port for create more dictionaries
			header[34] = byte(i) + 7
		}

		reader := bytes.NewReader(output.Bytes())

		r := newCFHReader(reader)
		buf := make([]byte, len(testIPv4UDPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})
}

func benchmarkCFHReaderReadEthernetIPv6TCP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv6TCPFrameHeader1))
		copy(header, testIPv6TCPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			header[61] = byte(i) + 2 // TCP Sequence [byte 4]
			header[65] = byte(i) + 3 // TCP acknowledgment [byte 4]
			header[70] = byte(i) + 4 // TCP checksum [byte 1]
			header[71] = byte(i) + 5 // TCP checksum [byte 2]
		}

		reader := bytes.NewReader(output.Bytes())

		r := newCFHReader(reader)
		buf := make([]byte, len(testIPv6TCPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv6TCPFrameHeader1))
		copy(header, testIPv6TCPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			header[61] = byte(i) + 2 // TCP Sequence [byte 4]
			header[65] = byte(i) + 3 // TCP acknowledgment [byte 4]
			header[70] = byte(i) + 4 // TCP checksum [byte 1]
			header[71] = byte(i) + 5 // TCP checksum [byte 2]

			// change destination port for create more dictionaries
			header[54] = byte(i) + 6
		}

		reader := bytes.NewReader(output.Bytes())

		r := newCFHReader(reader)
		buf := make([]byte, len(testIPv6TCPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})
}

func benchmarkCFHReaderReadEthernetIPv6UDP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv6UDPFrameHeader1))
		copy(header, testIPv6UDPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			header[59] = byte(i) + 2 // UDP length [byte 4]
			header[60] = byte(i) + 3 // UDP checksum [byte 1]
			header[61] = byte(i) + 4 // UDP checksum [byte 2]
		}

		reader := bytes.NewReader(output.Bytes())

		r := newCFHReader(reader)
		buf := make([]byte, len(testIPv6UDPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, len(testIPv6UDPFrameHeader1))
		copy(header, testIPv6UDPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			header[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			header[59] = byte(i) + 2 // UDP length [byte 4]
			header[60] = byte(i) + 3 // UDP checksum [byte 1]
			header[61] = byte(i) + 4 // UDP checksum [byte 2]

			// change destination port for create more dictionaries
			header[54] = byte(i) + 5
		}

		reader := bytes.NewReader(output.Bytes())

		r := newCFHReader(reader)
		buf := make([]byte, len(testIPv6UDPFrameHeader1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})
}

func benchmarkCFHReaderReadCustomFrameHeader(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, 64)
		copy(header, testIPv4TCPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// change a little
			for j := 0; j < len(header)/cfhMinDiffDiv-2; j++ {
				header[j] = byte(i) + 1
			}
		}

		reader := bytes.NewReader(output.Bytes())

		r := newCFHReader(reader)
		buf := make([]byte, len(header))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := newCFHWriter(output)

		header := make([]byte, 64)
		copy(header, testIPv4TCPFrameHeader1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(header)
			if err != nil {
				b.Fatal(err)
			}

			// change a little
			for j := 0; j < len(header)/cfhMaxDiffDiv+2; j++ {
				header[j] = byte(i) + 1
			}
		}

		reader := bytes.NewReader(output.Bytes())

		r := newCFHReader(reader)
		buf := make([]byte, len(header))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() != 0 {
				continue
			}
			_, err = reader.Seek(0, io.SeekStart)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StopTimer()
	})
}

func BenchmarkIsFrameHeaderPreferBeCompressed(b *testing.B) {
	b.Run("Ethernet IPv4 TCP", benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv4TCP)
	b.Run("Ethernet IPv4 UDP", benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv4UDP)
	b.Run("Ethernet IPv6 TCP", benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv6TCP)
	b.Run("Ethernet IPv6 UDP", benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv6UDP)
}

func benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv4TCP(b *testing.B) {
	header := make([]byte, len(testIPv4TCPFrameHeader1)+16)
	copy(header, testIPv4TCPFrameHeader1)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		size, prefer := isFrameHeaderPreferBeCompressed(header)
		if !prefer {
			b.Fatal("not prefer")
		}
		if size != cfhEthernetIPv4TCPSize {
			b.Fatal("invalid size")
		}
	}

	b.StopTimer()
}

func benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv4UDP(b *testing.B) {
	header := make([]byte, len(testIPv4UDPFrameHeader1)+16)
	copy(header, testIPv4UDPFrameHeader1)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		size, prefer := isFrameHeaderPreferBeCompressed(header)
		if !prefer {
			b.Fatal("not prefer")
		}
		if size != cfhEthernetIPv4UDPSize {
			b.Fatal("invalid size")
		}
	}

	b.StopTimer()
}

func benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv6TCP(b *testing.B) {
	header := make([]byte, len(testIPv6TCPFrameHeader1)+16)
	copy(header, testIPv6TCPFrameHeader1)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		size, prefer := isFrameHeaderPreferBeCompressed(header)
		if !prefer {
			b.Fatal("not prefer")
		}
		if size != cfhEthernetIPv6TCPSize {
			b.Fatal("invalid size")
		}
	}

	b.StopTimer()
}

func benchmarkIsFrameHeaderPreferBeCompressedEthernetIPv6UDP(b *testing.B) {
	header := make([]byte, len(testIPv6UDPFrameHeader1)+16)
	copy(header, testIPv6UDPFrameHeader1)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		size, prefer := isFrameHeaderPreferBeCompressed(header)
		if !prefer {
			b.Fatal("not prefer")
		}
		if size != cfhEthernetIPv6UDPSize {
			b.Fatal("invalid size")
		}
	}

	b.StopTimer()
}
