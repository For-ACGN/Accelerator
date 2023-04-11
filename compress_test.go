package accelerator

import (
	"bytes"
	"crypto/rand"
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
		require.Equal(t, err, io.ErrClosedPipe)
		require.Zero(t, n)

		n, err = w.Write(testIPv4TCPFrame1)
		require.Equal(t, err, io.ErrClosedPipe)
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
		require.Equal(t, err, io.ErrClosedPipe)
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
		require.Equal(t, err, io.ErrClosedPipe)
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
