package accelerator

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"sync"
	"testing"

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

	testIPv4TCPFrame1 = testMustDecodeHex(testEthernet1 + testIPv4H1 + testTCPH1)
	testIPv4TCPFrame2 = testMustDecodeHex(testEthernet1 + testIPv4H1 + testTCPH2)
	testIPv4TCPFrame3 = testMustDecodeHex(testEthernet1 + testIPv4H2 + testTCPH1)
	testIPv4TCPFrame4 = testMustDecodeHex(testEthernet1 + testIPv4H2 + testTCPH2)
	testIPv4TCPFrame5 = testMustDecodeHex(testEthernet2 + testIPv4H1 + testTCPH1)
	testIPv4TCPFrame6 = testMustDecodeHex(testEthernet2 + testIPv4H1 + testTCPH2)
	testIPv4TCPFrame7 = testMustDecodeHex(testEthernet2 + testIPv4H2 + testTCPH1)
	testIPv4TCPFrame8 = testMustDecodeHex(testEthernet2 + testIPv4H2 + testTCPH2)

	testIPv4UDPFrame1 = testMustDecodeHex(testEthernet1 + testIPv4H3 + testUDPH1)
	testIPv4UDPFrame2 = testMustDecodeHex(testEthernet1 + testIPv4H3 + testUDPH2)
	testIPv4UDPFrame3 = testMustDecodeHex(testEthernet1 + testIPv4H4 + testUDPH1)
	testIPv4UDPFrame4 = testMustDecodeHex(testEthernet1 + testIPv4H4 + testUDPH2)
	testIPv4UDPFrame5 = testMustDecodeHex(testEthernet2 + testIPv4H3 + testUDPH1)
	testIPv4UDPFrame6 = testMustDecodeHex(testEthernet2 + testIPv4H3 + testUDPH2)
	testIPv4UDPFrame7 = testMustDecodeHex(testEthernet2 + testIPv4H4 + testUDPH1)
	testIPv4UDPFrame8 = testMustDecodeHex(testEthernet2 + testIPv4H4 + testUDPH2)

	testIPv6TCPFrame1 = testMustDecodeHex(testEthernet3 + testIPv6H1 + testTCPH1)
	testIPv6TCPFrame2 = testMustDecodeHex(testEthernet3 + testIPv6H1 + testTCPH2)
	testIPv6TCPFrame3 = testMustDecodeHex(testEthernet3 + testIPv6H2 + testTCPH1)
	testIPv6TCPFrame4 = testMustDecodeHex(testEthernet3 + testIPv6H2 + testTCPH2)
	testIPv6TCPFrame5 = testMustDecodeHex(testEthernet4 + testIPv6H1 + testTCPH1)
	testIPv6TCPFrame6 = testMustDecodeHex(testEthernet4 + testIPv6H1 + testTCPH2)
	testIPv6TCPFrame7 = testMustDecodeHex(testEthernet4 + testIPv6H2 + testTCPH1)
	testIPv6TCPFrame8 = testMustDecodeHex(testEthernet4 + testIPv6H2 + testTCPH2)

	testIPv6UDPFrame1 = testMustDecodeHex(testEthernet3 + testIPv6H3 + testUDPH1)
	testIPv6UDPFrame2 = testMustDecodeHex(testEthernet3 + testIPv6H3 + testUDPH2)
	testIPv6UDPFrame3 = testMustDecodeHex(testEthernet3 + testIPv6H4 + testUDPH1)
	testIPv6UDPFrame4 = testMustDecodeHex(testEthernet3 + testIPv6H4 + testUDPH2)
	testIPv6UDPFrame5 = testMustDecodeHex(testEthernet4 + testIPv6H3 + testUDPH1)
	testIPv6UDPFrame6 = testMustDecodeHex(testEthernet4 + testIPv6H3 + testUDPH2)
	testIPv6UDPFrame7 = testMustDecodeHex(testEthernet4 + testIPv6H4 + testUDPH1)
	testIPv6UDPFrame8 = testMustDecodeHex(testEthernet4 + testIPv6H4 + testUDPH2)
)

var testFrames = [][]byte{
	testIPv4TCPFrame1, testIPv4TCPFrame2, testIPv4TCPFrame3, testIPv4TCPFrame4,
	testIPv4TCPFrame5, testIPv4TCPFrame6, testIPv4TCPFrame7, testIPv4TCPFrame8,

	testIPv4UDPFrame1, testIPv4UDPFrame2, testIPv4UDPFrame3, testIPv4UDPFrame4,
	testIPv4UDPFrame5, testIPv4UDPFrame6, testIPv4UDPFrame7, testIPv4UDPFrame8,

	testIPv6TCPFrame1, testIPv6TCPFrame2, testIPv6TCPFrame3, testIPv6TCPFrame4,
	testIPv6TCPFrame5, testIPv6TCPFrame6, testIPv6TCPFrame7, testIPv6TCPFrame8,

	testIPv6UDPFrame1, testIPv6UDPFrame2, testIPv6UDPFrame3, testIPv6UDPFrame4,
	testIPv6UDPFrame5, testIPv6UDPFrame6, testIPv6UDPFrame7, testIPv6UDPFrame8,
}

func testMustDecodeHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func TestNewCFHWriter(t *testing.T) {
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
}

func TestCFHWriter_Write(t *testing.T) {
	output := bytes.NewBuffer(make([]byte, 0, 4096))

	t.Run("write as same as the last", func(t *testing.T) {
		w := newCFHWriter(output)
		for i := 0; i < 100; i++ {
			n, err := w.Write(testIPv4TCPFrame1)
			require.NoError(t, err)
			require.Equal(t, len(testIPv4TCPFrame1), n)
		}

		r := newCFHReader(output)
		buf := make([]byte, len(testIPv4TCPFrame1))
		for i := 0; i < 100; i++ {
			n, err := r.Read(buf)
			require.NoError(t, err)
			require.Equal(t, len(testIPv4TCPFrame1), n)
			require.Equal(t, testIPv4TCPFrame1, buf)
		}
	})

	t.Run("write as same as the previous", func(t *testing.T) {
		w := newCFHWriter(output)

		n, err := w.Write(testIPv4TCPFrame1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrame1), n)

		n, err = w.Write(testIPv4TCPFrame2)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrame2), n)

		n, err = w.Write(testIPv4TCPFrame1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrame1), n)

		r := newCFHReader(output)

		buf := make([]byte, len(testIPv4TCPFrame1))
		n, err = r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrame1), n)
		require.Equal(t, testIPv4TCPFrame1, buf)

		buf = make([]byte, len(testIPv4TCPFrame2))
		n, err = r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrame2), n)
		require.Equal(t, testIPv4TCPFrame2, buf)

		buf = make([]byte, len(testIPv4TCPFrame1))
		n, err = r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrame1), n)
		require.Equal(t, testIPv4TCPFrame1, buf)
	})

	t.Run("write empty data", func(t *testing.T) {
		w := newCFHWriter(output)

		n, err := w.Write(nil)
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("write too large data", func(t *testing.T) {
		w := newCFHWriter(output)

		data := bytes.Repeat([]byte{0}, cfhMaxDataSize+1)
		n, err := w.Write(data)
		require.EqualError(t, err, "write too large data")
		require.Zero(t, n)
	})

	t.Run("write after appear error", func(t *testing.T) {
		pr, pw := io.Pipe()
		err := pr.Close()
		require.NoError(t, err)

		w := newCFHWriter(pw)

		n, err := w.Write(testIPv4TCPFrame1)
		require.Equal(t, io.ErrClosedPipe, err)
		require.Zero(t, n)

		n, err = w.Write(testIPv4TCPFrame1)
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

		n, err := w.Write(testIPv4TCPFrame1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrame1), n)

		wg.Wait()

		err = pr.Close()
		require.NoError(t, err)

		n, err = w.Write(testIPv4TCPFrame1)
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

		n, err := w.Write(testIPv4TCPFrame1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrame1), n)

		n, err = w.Write(testIPv4TCPFrame2)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrame2), n)

		wg.Wait()

		err = pr.Close()
		require.NoError(t, err)

		n, err = w.Write(testIPv4TCPFrame1)
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
		for _, f := range testFrames {
			n, err := w.Write(f)
			require.NoError(t, err)
			require.Equal(t, len(f), n)
		}

		r := newCFHReader(output)
		for _, f := range testFrames {
			buf := make([]byte, len(f))
			n, err := r.Read(buf)
			require.NoError(t, err)
			require.Equal(t, len(f), n)
			require.Equal(t, f, buf)
		}
	})

	t.Run("slow", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 4096))

		frames := testFrames
		for i := 0; i < 4; i++ {
			noise := make([]byte, 64)
			_, err := rand.Read(noise)
			require.NoError(t, err)
			frames = append(frames, noise)
		}

		w := newCFHWriter(output)
		for _, f := range frames {
			nf := append(f, 0)
			n, err := w.Write(nf)
			require.NoError(t, err)
			require.Equal(t, len(nf), n)
		}

		r := newCFHReader(output)
		for _, f := range frames {
			nf := append(f, 0)
			buf := make([]byte, len(nf))
			n, err := r.Read(buf)
			require.NoError(t, err)
			require.Equal(t, len(nf), n)
			require.Equal(t, nf, buf)
		}
	})
}

func TestNewCFHReader(t *testing.T) {
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
}

func TestCFHReader_Read(t *testing.T) {
	t.Run("read remaining data", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 128))

		w := newCFHWriter(output)

		n, err := w.Write(testIPv4TCPFrame1)
		require.NoError(t, err)
		require.Equal(t, len(testIPv4TCPFrame1), n)

		r := newCFHReader(output)

		buf1 := make([]byte, len(testIPv4TCPFrame1)-16)
		n, err = r.Read(buf1)
		require.NoError(t, err)
		require.Equal(t, len(buf1), n)

		buf2 := make([]byte, 16)
		n, err = r.Read(buf2)
		require.NoError(t, err)
		require.Equal(t, len(buf2), n)

		require.Equal(t, testIPv4TCPFrame1, append(buf1, buf2...))
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

		buf := make([]byte, 256)
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

		buf := make([]byte, 256)
		n, err := r.Read(buf)
		require.EqualError(t, err, "failed to read decompress command: EOF")
		require.Zero(t, n)
	})

	t.Run("invalid decompress command", func(t *testing.T) {
		output := bytes.NewBuffer(make([]byte, 0, 64))
		output.WriteByte(0)

		r := newCFHReader(output)

		buf := make([]byte, 256)
		n, err := r.Read(buf)
		require.EqualError(t, err, "invalid decompress command: 0")
		require.Zero(t, n)
	})

	t.Run("add dictionary", func(t *testing.T) {
		t.Run("failed to read dictionary size", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDAddDict)

			r := newCFHReader(output)

			buf := make([]byte, 256)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary size: EOF")
			require.Zero(t, n)
		})

		t.Run("read empty dictionary", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDAddDict)
			output.WriteByte(0) // dictionary size

			r := newCFHReader(output)

			buf := make([]byte, 256)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read empty dictionary")
			require.Zero(t, n)
		})

		t.Run("failed to read dictionary data", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDAddDict)
			output.WriteByte(1) // dictionary size

			r := newCFHReader(output)

			buf := make([]byte, 256)
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

			buf := make([]byte, 256)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary index: EOF")
			require.Zero(t, n)
		})

		t.Run("read invalid dictionary index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDData)
			output.WriteByte(0) // dictionary index

			r := newCFHReader(output)

			buf := make([]byte, 256)
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

			buf := make([]byte, 256)
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

			buf := make([]byte, 256)
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

			buf := make([]byte, 256)
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

			buf := make([]byte, 256)
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

			buf := make([]byte, 256)
			n, err := r.Read(buf)
			require.EqualError(t, err, "failed to read dictionary index: EOF")
			require.Zero(t, n)
		})

		t.Run("read invalid dictionary index", func(t *testing.T) {
			output := bytes.NewBuffer(make([]byte, 0, 64))
			output.WriteByte(cfhCMDPrev)
			output.WriteByte(0) // dictionary index

			r := newCFHReader(output)

			buf := make([]byte, 256)
			n, err := r.Read(buf)
			require.EqualError(t, err, "read invalid dictionary index: 0")
			require.Zero(t, n)
		})
	})
}

func TestCFHWriter_Fuzz(t *testing.T) {
	output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))

	frames := make([][]byte, 512*1024)
	typ := make([]byte, 1)
	idx := make([]byte, 2)
	for i := 0; i < len(frames); i++ {
		// select frame length
		_, err := rand.Read(typ)
		require.NoError(t, err)
		switch typ[0] % 5 {
		case 0: // IPv4 + TCP
			f := make([]byte, ethernetIPv4TCPFrameSize)
			copy(f, testIPv4TCPFrame1)
			// random change data
			for j := 0; j < 3; j++ {
				_, err = rand.Read(idx)
				require.NoError(t, err)
				index := binary.BigEndian.Uint16(idx) % ethernetIPv4TCPFrameSize
				f[index] = idx[1]
			}
			frames[i] = f
		case 1: // IPv4 + UDP
			f := make([]byte, ethernetIPv4UDPFrameSize)
			copy(f, testIPv4UDPFrame1)
			// random change data
			for j := 0; j < 2; j++ {
				_, err = rand.Read(idx)
				require.NoError(t, err)
				index := binary.BigEndian.Uint16(idx) % ethernetIPv4UDPFrameSize
				f[index] = idx[1]
			}
			frames[i] = f
		case 2: // IPv6 + TCP
			f := make([]byte, ethernetIPv6TCPFrameSize)
			copy(f, testIPv6TCPFrame1)
			// random change data
			for j := 0; j < 2; j++ {
				_, err = rand.Read(idx)
				require.NoError(t, err)
				index := binary.BigEndian.Uint16(idx) % ethernetIPv6TCPFrameSize
				f[index] = idx[1]
			}
			frames[i] = f
		case 3: // IPv6 + UDP
			f := make([]byte, ethernetIPv6UDPFrameSize)
			copy(f, testIPv6UDPFrame1)
			// random change data
			for j := 0; j < 1; j++ {
				_, err = rand.Read(idx)
				require.NoError(t, err)
				index := binary.BigEndian.Uint16(idx) % ethernetIPv6UDPFrameSize
				f[index] = idx[1]
			}
			frames[i] = f
		case 4: // random length
			sizeBuf := make([]byte, 1)
			var size byte
			for size < 16 {
				_, err = rand.Read(sizeBuf)
				require.NoError(t, err)
				size = sizeBuf[0]
			}
			f := make([]byte, size)
			_, err = rand.Read(f)
			require.NoError(t, err)
			frames[i] = f
		}
	}

	w := newCFHWriter(output)
	for _, f := range frames {
		n, err := w.Write(f)
		require.NoError(t, err)
		require.Equal(t, len(f), n)
	}

	r := newCFHReader(output)
	for _, f := range frames {
		buf := make([]byte, len(f))
		n, err := r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, len(f), n)
		require.Equal(t, f, buf)
	}
}

func TestCFHReader_Fuzz(t *testing.T) {
	data := make([]byte, 128)
	reader := bytes.NewReader(data)
	buf := make([]byte, 256)
	for i := 0; i < 1024*1024; i++ {
		_, err := rand.Read(data)
		require.NoError(t, err)
		_, err = reader.Seek(0, io.SeekStart)
		require.NoError(t, err)

		r := newCFHReader(reader)
		_, _ = r.Read(buf)
	}
}

func BenchmarkCFHWriter_Write(b *testing.B) {
	b.Run("Ethernet IPv4 TCP", benchmarkCFHWriterWriteEthernetIPv4TCP)
	b.Run("Ethernet IPv4 UDP", benchmarkCFHWriterWriteEthernetIPv4UDP)
	b.Run("Ethernet IPv6 TCP", benchmarkCFHWriterWriteEthernetIPv6TCP)
	b.Run("Ethernet IPv6 UDP", benchmarkCFHWriterWriteEthernetIPv6UDP)
}

func benchmarkCFHWriterWriteEthernetIPv4TCP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		f := make([]byte, len(testIPv4TCPFrame1))
		copy(f, testIPv4TCPFrame1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(f)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			f[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			f[19] = byte(i) + 2 // IPv4 ID [byte 2]
			f[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			f[41] = byte(i) + 4 // TCP Sequence [byte 4]
			f[45] = byte(i) + 5 // TCP acknowledgment [byte 4]
			f[50] = byte(i) + 6 // TCP checksum [byte 1]
			f[51] = byte(i) + 7 // TCP checksum [byte 2]
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		f := make([]byte, len(testIPv4TCPFrame1))
		copy(f, testIPv4TCPFrame1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(f)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			f[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			f[19] = byte(i) + 2 // IPv4 ID [byte 2]
			f[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			f[41] = byte(i) + 4 // TCP Sequence [byte 4]
			f[45] = byte(i) + 5 // TCP acknowledgment [byte 4]
			f[50] = byte(i) + 6 // TCP checksum [byte 1]
			f[51] = byte(i) + 7 // TCP checksum [byte 2]

			// change destination port for create more dictionaries
			f[34] = byte(i) + 8
		}

		b.StopTimer()
	})
}

func benchmarkCFHWriterWriteEthernetIPv4UDP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		f := make([]byte, len(testIPv4UDPFrame1))
		copy(f, testIPv4UDPFrame1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(f)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			f[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			f[19] = byte(i) + 2 // IPv4 ID [byte 2]
			f[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			f[39] = byte(i) + 4 // UDP length [byte 4]
			f[40] = byte(i) + 5 // UDP checksum [byte 1]
			f[41] = byte(i) + 6 // UDP checksum [byte 2]
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		f := make([]byte, len(testIPv4UDPFrame1))
		copy(f, testIPv4UDPFrame1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(f)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			f[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			f[19] = byte(i) + 2 // IPv4 ID [byte 2]
			f[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			f[39] = byte(i) + 4 // UDP length [byte 4]
			f[40] = byte(i) + 5 // UDP checksum [byte 1]
			f[41] = byte(i) + 6 // UDP checksum [byte 2]

			// change destination port for create more dictionaries
			f[34] = byte(i) + 7
		}

		b.StopTimer()
	})
}

func benchmarkCFHWriterWriteEthernetIPv6TCP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		f := make([]byte, len(testIPv6TCPFrame1))
		copy(f, testIPv6TCPFrame1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(f)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			f[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			f[61] = byte(i) + 2 // TCP Sequence [byte 4]
			f[65] = byte(i) + 3 // TCP acknowledgment [byte 4]
			f[70] = byte(i) + 4 // TCP checksum [byte 1]
			f[71] = byte(i) + 5 // TCP checksum [byte 2]
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		f := make([]byte, len(testIPv6TCPFrame1))
		copy(f, testIPv6TCPFrame1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(f)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			f[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			f[61] = byte(i) + 2 // TCP Sequence [byte 4]
			f[65] = byte(i) + 3 // TCP acknowledgment [byte 4]
			f[70] = byte(i) + 4 // TCP checksum [byte 1]
			f[71] = byte(i) + 5 // TCP checksum [byte 2]

			// change destination port for create more dictionaries
			f[54] = byte(i) + 6
		}

		b.StopTimer()
	})
}

func benchmarkCFHWriterWriteEthernetIPv6UDP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		f := make([]byte, len(testIPv6UDPFrame1))
		copy(f, testIPv6UDPFrame1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(f)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			f[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			f[59] = byte(i) + 2 // UDP length [byte 4]
			f[60] = byte(i) + 3 // UDP checksum [byte 1]
			f[61] = byte(i) + 4 // UDP checksum [byte 2]
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 64*1024*1024))
		w := newCFHWriter(output)

		f := make([]byte, len(testIPv6UDPFrame1))
		copy(f, testIPv6UDPFrame1)

		b.ReportAllocs()
		b.ResetTimer()

		var err error
		for i := 0; i < b.N; i++ {
			_, err = w.Write(f)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			f[19] = byte(i) + 1 // IPv6 payload length [byte 2]

			f[59] = byte(i) + 2 // UDP length [byte 4]
			f[60] = byte(i) + 3 // UDP checksum [byte 1]
			f[61] = byte(i) + 4 // UDP checksum [byte 2]

			// change destination port for create more dictionaries
			f[54] = byte(i) + 5
		}

		b.StopTimer()
	})
}

func BenchmarkCFHReader_Read(b *testing.B) {
	b.Run("Ethernet IPv4 TCP", benchmarkCFHReaderReadEthernetIPv4TCP)
	b.Run("Ethernet IPv4 UDP", benchmarkCFHReaderReadEthernetIPv4UDP)
	b.Run("Ethernet IPv6 TCP", benchmarkCFHReaderReadEthernetIPv6TCP)
	b.Run("Ethernet IPv6 UDP", benchmarkCFHReaderReadEthernetIPv6UDP)
}

func benchmarkCFHReaderReadEthernetIPv4TCP(b *testing.B) {
	b.Run("single dictionary", func(b *testing.B) {
		output := bytes.NewBuffer(make([]byte, 0, 1024*1024))
		w := newCFHWriter(output)

		f := make([]byte, len(testIPv4TCPFrame1))
		copy(f, testIPv4TCPFrame1)

		var err error
		for i := 0; i < 1024; i++ {
			_, err = w.Write(f)
			if err != nil {
				b.Fatal(err)
			}

			// data that change frequently
			f[17] = byte(i) + 1 // IPv4 Total Length [byte 2]
			f[19] = byte(i) + 2 // IPv4 ID [byte 2]
			f[25] = byte(i) + 3 // IPv4 checksum [byte 2]

			f[41] = byte(i) + 4 // TCP Sequence [byte 4]
			f[45] = byte(i) + 5 // TCP acknowledgment [byte 4]
			f[50] = byte(i) + 6 // TCP checksum [byte 1]
			f[51] = byte(i) + 7 // TCP checksum [byte 2]
		}

		reader := bytes.NewReader(output.Bytes())

		r := newCFHReader(reader)
		buf := make([]byte, len(testIPv4TCPFrame1))

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err = r.Read(buf)
			if err != nil {
				b.Fatal(err)
			}

			if reader.Len() == 0 {
				_, err = reader.Seek(0, io.SeekStart)
				if err != nil {
					b.Fatal(err)
				}
			}
		}

		b.StopTimer()
	})

	b.Run("multi dictionaries", func(b *testing.B) {

	})
}

func benchmarkCFHReaderReadEthernetIPv4UDP(b *testing.B) {

}

func benchmarkCFHReaderReadEthernetIPv6TCP(b *testing.B) {

}

func benchmarkCFHReaderReadEthernetIPv6UDP(b *testing.B) {

}
